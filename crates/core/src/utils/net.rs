//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::error::code::ErrorCode;
use crate::raise_error;
use crate::settings::proxy::Proxy;
use crate::utils::tls::establish_tls_stream;
use crate::{error::BichonResult, imap::session::SessionStream};
use base64::{engine::general_purpose, Engine as _};
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_io_timeout::TimeoutStream;
use tokio_socks::tcp::Socks5Stream;
use tracing::error;
use url::Url;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyScheme {
    Socks5,
    Http,
}

impl ProxyScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }
}

pub(crate) struct ParsedProxyUrl {
    pub(crate) scheme: ProxyScheme,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
}

impl ParsedProxyUrl {
    fn standard_url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                format!(
                    "{}://{}:{}@{}:{}",
                    self.scheme.as_str(),
                    encode_proxy_credential(username),
                    encode_proxy_credential(password),
                    self.host,
                    self.port
                )
            }
            _ => format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port),
        }
    }

    fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub(crate) async fn establish_tcp_connection_with_timeout(
    address: SocketAddr,
    use_proxy: Option<u64>,
) -> BichonResult<Pin<Box<TimeoutStream<TcpStream>>>> {
    // Establish the TCP connection with a timeout
    let tcp_stream = connect_with_optional_proxy(use_proxy, address).await?;
    let mut timeout_stream = TimeoutStream::new(tcp_stream);

    // Set read and write timeouts
    timeout_stream.set_write_timeout(Some(Duration::from_secs(15)));
    timeout_stream.set_read_timeout(Some(Duration::from_secs(30)));

    // Return the timeout-wrapped TCP stream as a Pin
    Ok(Box::pin(timeout_stream))
}

pub async fn establish_tls_connection(
    address: SocketAddr,
    server_hostname: &str,
    alpn_protocols: &[&str],
    use_proxy: Option<u64>,
    dangerous: bool,
) -> BichonResult<impl SessionStream> {
    // Establish the TCP connection with timeout
    let tcp_stream = establish_tcp_connection_with_timeout(address, use_proxy).await?;

    // Wrap the TCP stream with TLS encryption
    let tls_stream =
        establish_tls_stream(server_hostname, alpn_protocols, tcp_stream, dangerous).await?;

    // Return the TLS stream wrapped in a SessionStream
    Ok(tls_stream)
}

pub(crate) fn parse_proxy_url(input: &str) -> BichonResult<ParsedProxyUrl> {
    match Url::parse(input) {
        Ok(url) => parse_standard_proxy_url(url, input),
        Err(_) => parse_provider_proxy_url(input),
    }
}

fn parse_standard_proxy_url(url: Url, input: &str) -> BichonResult<ParsedProxyUrl> {
    let scheme = validate_proxy_scheme(url.scheme(), input)?;
    let host = url.host_str().ok_or_else(|| {
        raise_error!(
            "Proxy hostname cannot be empty".into(),
            ErrorCode::InvalidParameter
        )
    })?;
    let username = (!url.username().is_empty()).then(|| decode_proxy_credential(url.username()));
    let password = url.password().map(decode_proxy_credential);

    if username.is_some() && password.as_deref().unwrap_or_default().is_empty() {
        return Err(raise_error!(
            "Password cannot be empty when username is provided".into(),
            ErrorCode::InvalidParameter
        ));
    }

    Ok(ParsedProxyUrl {
        scheme,
        host: parse_proxy_host(host)?,
        port: url.port().unwrap_or(1080),
        username,
        password,
    })
}

fn parse_provider_proxy_url(input: &str) -> BichonResult<ParsedProxyUrl> {
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| invalid_proxy_url(input))?;
    let scheme = validate_proxy_scheme(scheme, input)?;
    let mut parts = rest.splitn(4, ':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next().ok_or_else(|| invalid_proxy_url(input))?;
    let username = parts.next().ok_or_else(|| invalid_proxy_url(input))?;
    let password = parts.next().ok_or_else(|| {
        raise_error!(
            "Password cannot be empty when username is provided".into(),
            ErrorCode::InvalidParameter
        )
    })?;

    if username.is_empty() || password.is_empty() {
        return Err(raise_error!(
            "Proxy username and password cannot be empty".into(),
            ErrorCode::InvalidParameter
        ));
    };

    Ok(ParsedProxyUrl {
        scheme,
        host: parse_proxy_host(host)?,
        port: parse_proxy_port(port)?,
        username: Some(username.to_string()),
        password: Some(password.to_string()),
    })
}

pub(crate) fn normalize_proxy_url(input: &str) -> BichonResult<String> {
    Ok(parse_proxy_url(input)?.standard_url())
}

fn validate_proxy_scheme(scheme: &str, _input: &str) -> BichonResult<ProxyScheme> {
    match scheme.to_ascii_lowercase().as_str() {
        "socks5" => Ok(ProxyScheme::Socks5),
        "http" => Ok(ProxyScheme::Http),
        _ => Err(raise_error!(
            "Invalid proxy URL: must start with 'http://' or 'socks5://'".into(),
            ErrorCode::InvalidParameter
        )),
    }
}

fn parse_proxy_host(host: &str) -> BichonResult<String> {
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(raise_error!(
            "Hostname contains invalid characters".into(),
            ErrorCode::InvalidParameter
        ));
    }
    Ok(host.to_string())
}

fn parse_proxy_port(port: &str) -> BichonResult<u16> {
    let port = port.parse::<u16>().map_err(|e| {
        raise_error!(
            format!("Failed to parse proxy port '{}': {}", port, e),
            ErrorCode::InvalidParameter
        )
    })?;

    if port == 0 {
        return Err(raise_error!(
            "Port must be between 1-65535".into(),
            ErrorCode::InvalidParameter
        ));
    }

    Ok(port)
}

fn invalid_proxy_url(_input: &str) -> crate::error::BichonError {
    raise_error!(
        "Invalid proxy URL: expected scheme://host:port, scheme://username:password@host:port, or scheme://host:port:username:password".into(),
        ErrorCode::InvalidParameter
    )
}

fn encode_proxy_credential(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn decode_proxy_credential(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    decoded.push(byte);
                    index += 3;
                    continue;
                }
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_proxy_url_preserves_standard_auth_url() {
        assert_eq!(
            normalize_proxy_url("socks5://user:pass@proxy.example.com:1080").unwrap(),
            "socks5://user:pass@proxy.example.com:1080"
        );
    }

    #[test]
    fn normalize_proxy_url_encodes_standard_auth_url() {
        assert_eq!(
            normalize_proxy_url("socks5://user:p%40ss@proxy.example.com:1080").unwrap(),
            "socks5://user:p%40ss@proxy.example.com:1080"
        );
    }

    #[test]
    fn normalize_proxy_url_adds_default_port() {
        assert_eq!(
            normalize_proxy_url("socks5://proxy.example.com").unwrap(),
            "socks5://proxy.example.com:1080"
        );
    }

    #[test]
    fn normalize_proxy_url_converts_provider_colon_auth_url() {
        assert_eq!(
            normalize_proxy_url("socks5://server.nodeprovider.com:8080:user:pass").unwrap(),
            "socks5://user:pass@server.nodeprovider.com:8080"
        );
    }

    #[test]
    fn normalize_proxy_url_rejects_ipv6_url() {
        assert!(normalize_proxy_url("socks5://[::1]:1080").is_err());
    }
}

/// Try to connect via proxy or TCP with timeout
async fn connect_with_optional_proxy(
    use_proxy: Option<u64>,
    address: SocketAddr,
) -> BichonResult<TcpStream> {
    // Try if proxy is enabled
    if let Some(proxy_id) = use_proxy {
        let proxy = Proxy::get(proxy_id)?;
        let proxy = parse_proxy_url(&proxy.url)?;
        return if proxy.scheme == ProxyScheme::Http {
            connect_via_http_proxy(&proxy, address).await
        } else {
            connect_via_socks5_proxy(&proxy, address).await
        };
    }
    // Fallback to direct TCP connection
    timeout(TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            error!(
                "TCP connection to {} timed out after {}s",
                address,
                TIMEOUT.as_secs()
            );
            raise_error!(
                format!(
                    "TCP connection to {} timed out after {}s",
                    address,
                    TIMEOUT.as_secs()
                ),
                ErrorCode::ConnectionTimeout
            )
        })?
        .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::NetworkError))
}

async fn connect_via_socks5_proxy(
    proxy: &ParsedProxyUrl,
    address: SocketAddr,
) -> BichonResult<TcpStream> {
    let proxy_addr = proxy.address();
    let stream = match (&proxy.username, &proxy.password) {
        (Some(username), Some(password)) => {
            timeout(
                TIMEOUT,
                Socks5Stream::connect_with_password(
                    (proxy.host.as_str(), proxy.port),
                    address,
                    username,
                    password,
                ),
            )
            .await
        }
        _ => {
            timeout(
                TIMEOUT,
                Socks5Stream::connect((proxy.host.as_str(), proxy.port), address),
            )
            .await
        }
    };

    stream
        .map_err(|_| {
            error!(
                "SOCKS5 proxy connection to {} via {} timed out after {}s",
                address,
                proxy_addr,
                TIMEOUT.as_secs()
            );
            raise_error!(
                format!(
                    "SOCKS5 proxy connection to {} via {} timed out after {}s",
                    address,
                    proxy_addr,
                    TIMEOUT.as_secs()
                ),
                ErrorCode::ConnectionTimeout
            )
        })?
        .map(|s| s.into_inner())
        .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::NetworkError))
}

async fn connect_via_http_proxy(
    proxy: &ParsedProxyUrl,
    address: SocketAddr,
) -> BichonResult<TcpStream> {
    let proxy_addr = proxy.address();
    let mut stream = timeout(
        TIMEOUT,
        TcpStream::connect((proxy.host.as_str(), proxy.port)),
    )
    .await
    .map_err(|_| {
        raise_error!(
            format!(
                "HTTP proxy connection to {} timed out after {}s",
                proxy_addr,
                TIMEOUT.as_secs()
            ),
            ErrorCode::ConnectionTimeout
        )
    })?
    .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::NetworkError))?;

    let mut request = format!(
        "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
        let auth = general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
    }
    request.push_str("\r\n");

    timeout(TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| {
            raise_error!(
                format!(
                    "HTTP proxy CONNECT to {} via {} timed out after {}s",
                    address,
                    proxy_addr,
                    TIMEOUT.as_secs()
                ),
                ErrorCode::ConnectionTimeout
            )
        })?
        .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::NetworkError))?;

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        timeout(TIMEOUT, stream.read_exact(&mut byte))
            .await
            .map_err(|_| {
                raise_error!(
                    format!(
                        "HTTP proxy CONNECT response from {} timed out after {}s",
                        proxy_addr,
                        TIMEOUT.as_secs()
                    ),
                    ErrorCode::ConnectionTimeout
                )
            })?
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::NetworkError))?;
        response.push(byte[0]);
        if response.len() > 8192 {
            return Err(raise_error!(
                "HTTP proxy CONNECT response headers are too large".into(),
                ErrorCode::NetworkError
            ));
        }
    }

    let response = String::from_utf8_lossy(&response);
    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
        Ok(stream)
    } else {
        Err(raise_error!(
            format!(
                "HTTP proxy CONNECT to {} via {} failed: {}",
                address,
                proxy_addr,
                response.lines().next().unwrap_or("invalid response")
            ),
            ErrorCode::NetworkError
        ))
    }
}

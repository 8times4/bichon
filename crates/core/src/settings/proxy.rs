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

//use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use std::{error::Error, time::Duration};

use crate::{
    database::{
        delete_impl, find_impl, insert_impl, list_all_impl, manager::DB_MANAGER, update_impl,
        MemDbModel,
    },
    error::{code::ErrorCode, BichonResult},
    id, raise_error, utc_now,
    utils::net::{normalize_proxy_url, parse_proxy_url},
};

const PROXY_TEST_TIMEOUT: Duration = Duration::from_secs(8);
const GEO_PROVIDERS: &[GeoProvider] = &[
    GeoProvider {
        name: "ip-api.com",
        url: "http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,isp,timezone,lat,lon",
    },
    GeoProvider {
        name: "ipwho.is",
        url: "https://ipwho.is/",
    },
    GeoProvider {
        name: "ipapi.co",
        url: "https://ipapi.co/json/",
    },
];

struct GeoProvider {
    name: &'static str,
    url: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Object))]
pub struct Proxy {
    /// The unique identifier for this proxy configuration.
    pub id: u64,

    /// The proxy URL (e.g., socks5://127.0.0.1:1080) used to route network requests.
    pub url: String,

    /// The creation timestamp of this record, represented as milliseconds since the Unix epoch.
    pub created_at: i64,

    /// The last update timestamp of this record, represented as milliseconds since the Unix epoch.
    pub updated_at: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "web-api", derive(poem_openapi::Object))]
pub struct ProxyTestResult {
    pub ip: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
}

impl MemDbModel for Proxy {
    fn collection() -> &'static str {
        "proxies"
    }
    fn key(&self) -> String {
        self.id.to_string()
    }
}

impl Proxy {
    /// Create a new Proxy instance with the given URL and timestamps.
    pub fn new(url: String) -> Self {
        Self {
            id: id!(64),
            url,
            created_at: utc_now!(),
            updated_at: utc_now!(),
        }
    }

    pub fn get(id: u64) -> BichonResult<Proxy> {
        let key = id.to_string();
        find_impl::<Proxy>(DB_MANAGER.db(), &key)?.ok_or_else(|| {
            raise_error!(
                format!("Proxy with id={} not found", id),
                ErrorCode::ResourceNotFound
            )
        })
    }

    pub fn list_all() -> BichonResult<Vec<Proxy>> {
        list_all_impl::<Proxy>(DB_MANAGER.db())
    }

    pub fn delete(id: u64) -> BichonResult<()> {
        delete_impl::<Proxy>(DB_MANAGER.db(), &id.to_string())
    }

    pub fn update(id: u64, url: String) -> BichonResult<()> {
        update_impl(DB_MANAGER.db(), &id.to_string(), move |current: Proxy| {
            let mut updated = current.clone();
            updated.url = url;
            updated.updated_at = utc_now!();
            updated.validate()?;
            Ok(updated)
        })?;
        Ok(())
    }

    pub fn save(&self) -> BichonResult<()> {
        self.validate()?;
        insert_impl(DB_MANAGER.db(), self.to_owned())
    }

    /// Validate that the URL is a supported proxy URL.
    pub fn validate(&self) -> BichonResult<()> {
        parse_proxy_url(&self.url)?;
        Ok(())
    }

    pub async fn test_connectivity(&self) -> BichonResult<ProxyTestResult> {
        test_proxy_url(&self.url).await
    }

    pub async fn test(id: u64) -> BichonResult<ProxyTestResult> {
        let proxy = Self::get(id)?;
        proxy.test_connectivity().await
    }
}

async fn test_proxy_url(url: &str) -> BichonResult<ProxyTestResult> {
    let proxy_url = normalize_proxy_url(url)?;
    let client = reqwest::Client::builder()
        .timeout(PROXY_TEST_TIMEOUT)
        .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| {
            raise_error!(
                format!("Failed to configure proxy: {}", e),
                ErrorCode::InvalidParameter
            )
        })?)
        .build()
        .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError))?;

    let mut last_error = None;
    for provider in GEO_PROVIDERS {
        match test_geo_provider(&client, provider).await {
            Ok(result) => return Ok(result),
            Err(err) => last_error = Some(err.to_string()),
        }
    }

    Err(raise_error!(
        format!(
            "Proxy test failed with all geo providers: {}",
            last_error.unwrap_or_else(|| "unknown error".into())
        ),
        ErrorCode::NetworkError
    ))
}

async fn test_geo_provider(
    client: &reqwest::Client,
    provider: &GeoProvider,
) -> BichonResult<ProxyTestResult> {
    let value = client
        .get(provider.url)
        .send()
        .await
        .map_err(|e| {
            raise_error!(
                proxy_request_error_message(
                    &format!("Proxy test request failed via {}", provider.name),
                    &e
                ),
                ErrorCode::NetworkError
            )
        })?
        .error_for_status()
        .map_err(|e| {
            raise_error!(
                proxy_request_error_message(
                    &format!("Proxy test request failed via {}", provider.name),
                    &e
                ),
                ErrorCode::NetworkError
            )
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| {
            raise_error!(
                proxy_request_error_message(
                    &format!("Failed to read proxy test response from {}", provider.name),
                    &e
                ),
                ErrorCode::NetworkError
            )
        })?;

    proxy_test_result_from_value(provider.name, &value)
}

fn proxy_test_result_from_value(
    provider: &str,
    value: &serde_json::Value,
) -> BichonResult<ProxyTestResult> {
    if provider == "ip-api.com" && value["status"].as_str() == Some("fail") {
        return Err(raise_error!(
            format!(
                "ip-api.com proxy test failed: {}",
                value["message"].as_str().unwrap_or("unknown error")
            ),
            ErrorCode::NetworkError
        ));
    }
    let connection = &value["connection"];

    Ok(ProxyTestResult {
        ip: value[if provider == "ip-api.com" {
            "query"
        } else {
            "ip"
        }]
        .as_str()
        .map(str::to_string),
        country: value[if provider == "ipapi.co" {
            "country_name"
        } else {
            "country"
        }]
        .as_str()
        .map(str::to_string),
        region: value[if provider == "ip-api.com" {
            "regionName"
        } else {
            "region"
        }]
        .as_str()
        .map(str::to_string),
        city: value["city"].as_str().map(str::to_string),
        isp: if provider == "ipapi.co" {
            value["org"].as_str().map(str::to_string)
        } else if provider == "ip-api.com" {
            value["isp"].as_str().map(str::to_string)
        } else {
            connection["isp"].as_str().map(str::to_string)
        },
    })
}

fn proxy_request_error_message(context: &str, err: &reqwest::Error) -> String {
    let kind = if err.is_timeout() {
        "timed out"
    } else if err.is_connect() {
        "could not connect through the proxy"
    } else if err.is_status() {
        "received an error response"
    } else {
        "request failed"
    };
    let mut message = format!("{context}: {kind}: {err}");
    let mut source = err.source();

    while let Some(err) = source {
        message.push_str(&format!(": {err}"));
        source = err.source();
    }

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_provider_colon_auth_url() {
        let proxy = Proxy::new("socks5://server.nodeprovider.com:8080:user:pass".to_string());

        assert!(proxy.validate().is_ok());
    }
}

const providerProxyUrl =
  /^(socks5|http):\/\/([^:\s]+):(\d+):([^:\s]+):(.+)$/i

function parseProxyUrl(value: string): URL | null {
  const match = providerProxyUrl.exec(value)
  const url = match
    ? `${match[1].toLowerCase()}://${match[4]}:${match[5]}@${match[2]}:${match[3]}`
    : value

  try {
    return new URL(url)
  } catch (_e) {
    return null
  }
}

export function formatProxyDisplayUrl(url: string): string {
  const parsed = parseProxyUrl(url)
  if (!parsed) return url

  const protocol = parsed.protocol.replace(':', '')
  const endpoint = `${protocol}://${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}`

  const hints: string[] = []
  const country = url.match(/(?:^|[-_:])country-([a-z]{2})(?:[-_:]|$)/i)?.[1]
  if (country) hints.push(country.toUpperCase())

  const region = url.match(/(?:^|[-_:])region-([^-_:]+)/i)?.[1]
  if (region) hints.push(region)

  const hasAuth = Boolean(parsed.username || parsed.password)
  const suffix =
    hints.length > 0 ? hints.join(' · ') : hasAuth ? 'auth' : null

  return suffix ? `${endpoint} · ${suffix}` : endpoint
}

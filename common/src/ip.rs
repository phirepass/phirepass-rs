use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Resolve the original client IP from proxy headers.
///
/// For `X-Forwarded-For`, we always take the left-most entry because it is the
/// original client in standard proxy chains.
pub fn resolve_client_ip(headers: &HeaderMap, fallback: IpAddr) -> IpAddr {
    if let Some(ip) = parse_x_forwarded_for(headers) {
        return ip;
    }

    if let Some(ip) = parse_forwarded_for(headers) {
        return ip;
    }

    fallback
}

fn parse_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;

    value.split(',').map(str::trim).find_map(parse_ip_token)
}

fn parse_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("forwarded")?.to_str().ok()?;

    // RFC 7239 format example:
    // Forwarded: for=203.0.113.60;proto=http;by=203.0.113.43
    // Forwarded: for="[2001:db8:cafe::17]:4711"
    // We still use the first `for=` match because it represents the left-most client.
    for segment in value.split(',') {
        for part in segment.split(';') {
            let part = part.trim();
            if let Some(raw) = part.strip_prefix("for=") {
                let raw = raw.trim().trim_matches('"');
                if let Some(ip) = parse_ip_token(raw) {
                    return Some(ip);
                }
            }
        }
    }

    None
}

fn parse_ip_token(raw: &str) -> Option<IpAddr> {
    if raw.is_empty() || raw.eq_ignore_ascii_case("unknown") {
        return None;
    }

    // IPv6 in Forwarded can be emitted as [addr]:port.
    let without_brackets = raw.trim_matches(|c| c == '[' || c == ']');

    if let Ok(ip) = without_brackets.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    if let Ok(addr) = without_brackets.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn takes_left_most_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("200.55.66.11, 192.168.1.1"),
        );

        let fallback = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = resolve_client_ip(&headers, fallback);

        assert_eq!(result, IpAddr::V4(Ipv4Addr::new(200, 55, 66, 11)));
    }

    #[test]
    fn falls_back_when_header_is_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("unknown"));

        let fallback = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = resolve_client_ip(&headers, fallback);

        assert_eq!(result, fallback);
    }
}

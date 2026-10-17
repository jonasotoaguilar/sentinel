//! Bounded single-attempt HTTP adapter for [`Explainer`](super::Explainer):
//! one POST per scan, at most 20 findings and 4096 bytes of redacted
//! context, a 10-second timeout, no retries. Transport failures become
//! [`ExplainError::Failed`], malformed bodies [`ExplainError::Invalid`].
//! Findings arrive already redacted, so nothing re-redacts here. HTTPS is
//! required; plain HTTP only for loopback (hermetic tests, no TLS).

use std::time::Duration;

use super::{ExplainError, Explainer, Explanation};
use crate::engine::secrets::SecretsEngine;
use crate::finding::Finding;

/// At most this many findings travel in the single request, canonical order.
pub const MAX_FINDINGS: usize = 20;
/// At most this many serialized bytes of finding context leave the process.
pub const MAX_CONTEXT_BYTES: usize = 4096;
/// Per-request timeout (spec: at most 10 seconds).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on the response body, mirroring the OSV client's bound.
const RESPONSE_LIMIT: u64 = 1024 * 1024;
const ENV_URL: &str = "SENTINEL_EXPLAIN_URL";
const ENV_API_KEY: &str = "SENTINEL_EXPLAIN_API_KEY";

/// HTTP [`Explainer`]: a single bounded POST per scan. Built without I/O;
/// the only request happens inside [`Explainer::explain`], exactly once.
pub struct HttpExplainer {
    agent: ureq::Agent,
    url: String,
    api_key: String,
    timeout: Duration,
}

impl HttpExplainer {
    /// Builds from explicit values; `None` for an empty value or a
    /// disallowed endpoint (non-HTTPS outside loopback). Never performs I/O.
    pub fn maybe_new(url: &str, api_key: &str) -> Option<Self> {
        Self::with_timeout(url, api_key, REQUEST_TIMEOUT)
    }

    /// Reads the endpoint and credential once from the environment; `None`
    /// keeps the pipeline on the disabled explainer (no HTTP). Never I/O.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var(ENV_URL).ok()?;
        let api_key = std::env::var(ENV_API_KEY).ok()?;
        Self::maybe_new(url.trim(), api_key.trim())
    }

    /// The configured per-request timeout (the 10-second evidence hook).
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    fn with_timeout(url: &str, api_key: &str, timeout: Duration) -> Option<Self> {
        let url = url.trim();
        if url.is_empty() || api_key.is_empty() || !is_allowed_url(url) {
            return None;
        }
        // No `https_only` on the agent: loopback HTTP must stay reachable
        // for hermetic tests, so the scheme gate above owns the guarantee.
        // The proxy is always disabled: honouring `HTTP_PROXY` would tunnel
        // the bearer token and the redacted payload to a third host.
        // Redirects are never followed: the contract allows at most one
        // request per scan, so a 3xx degrades like any other non-success.
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .proxy(None)
            .max_redirects(0)
            .build();
        Some(Self {
            agent: ureq::Agent::new_with_config(config),
            url: url.to_string(),
            api_key: api_key.to_string(),
            timeout,
        })
    }

    /// Serializes the request body: the findings prefix fitting the count
    /// and byte budgets, in canonical order. The byte budget covers the
    /// whole serialized body that leaves the process — entries, commas,
    /// and the envelope — never just the entries. Pure, so budgets are
    /// unit testable without a network. The returned document passes
    /// through the production secret table as defence in depth: per-field
    /// redaction upstream covers the known fields, and this pass covers
    /// whatever any field — present or future — contains. Every table
    /// match is longer than the placeholder, so redaction only shrinks
    /// the body and the byte budget above still holds.
    fn body(findings: &[Finding]) -> String {
        let mut entries = Vec::new();
        for finding in findings.iter().take(MAX_FINDINGS) {
            entries.push(serde_json::json!({
                "id": &finding.id,
                "rule_id": &finding.rule_id,
                "severity": finding.severity.to_string(),
                "path": &finding.location.path,
                "line": finding.location.line,
                "column": finding.location.column,
                "snippet": &finding.location.snippet,
                "message": &finding.message,
                "evidence": &finding.evidence,
            }));
            if serde_json::json!({ "findings": entries }).to_string().len() > MAX_CONTEXT_BYTES {
                entries.pop();
                break;
            }
        }
        let serialized = serde_json::json!({ "findings": entries }).to_string();
        SecretsEngine::redact_production(&serialized)
    }

    /// Parses the response envelope: an array of `{id, text}` objects with
    /// string fields. Anything else is [`ExplainError::Invalid`]; unknown
    /// ids travel through and the pipeline drops them. Text passes through
    /// verbatim: sanitization stays at the renderer boundary.
    fn parse(text: &str) -> Result<Vec<Explanation>, String> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|error| error.to_string())?;
        let items = value
            .as_array()
            .ok_or_else(|| "expected an array of {id, text} objects".to_string())?;
        items
            .iter()
            .map(|item| {
                let id = item
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "entry without a string id".to_string())?;
                let text = item
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "entry without string text".to_string())?;
                Ok(Explanation {
                    finding_id: id.to_string(),
                    text: text.to_string(),
                })
            })
            .collect()
    }
}

/// HTTPS everywhere; plain HTTP only for loopback (hermetic tests, no TLS).
/// Any URL carrying userinfo is refused on every scheme, and the host is
/// parsed as a host: bracketed IPv6 honours the brackets, otherwise the
/// authority up to the first colon. A bare `127.0.0.1` prefix inside
/// userinfo therefore never reads as the host.
fn is_allowed_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let (https, rest) = if let Some(rest) = lower.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if https {
        return true;
    }
    if let Some(inner) = authority.strip_prefix('[') {
        // Bracketed IPv6: the host ends at `]`, optionally followed by a port.
        let (host, after) = match inner.split_once(']') {
            Some(pair) => pair,
            None => return false,
        };
        return host == "::1" && (after.is_empty() || after.starts_with(':'));
    }
    let host = authority.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

impl Explainer for HttpExplainer {
    fn is_configured(&self) -> bool {
        true
    }

    fn explain(&self, findings: &[Finding]) -> Result<Vec<Explanation>, ExplainError> {
        if findings.is_empty() {
            return Ok(Vec::new());
        }
        let authorization = format!("Bearer {}", self.api_key);
        // A single attempt: every error path below returns without retrying.
        match self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Authorization", &authorization)
            .send(Self::body(findings).as_str())
        {
            Ok(mut response) if response.status().is_success() => {
                let text = response
                    .body_mut()
                    .with_config()
                    .limit(RESPONSE_LIMIT)
                    .read_to_string()
                    .map_err(|error| ExplainError::Failed(error.to_string()))?;
                Self::parse(&text).map_err(ExplainError::Invalid)
            }
            Ok(response) => Err(ExplainError::Failed(format!(
                "unexpected status {}",
                response.status()
            ))),
            Err(error) => Err(ExplainError::Failed(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Severity};
    use std::net::TcpListener;
    use std::time::Duration;

    fn finding(id: &str, snippet: &str) -> Finding {
        Finding {
            id: id.to_string(),
            engine: "secrets".to_string(),
            rule_id: "SECRET-synthetic-token".to_string(),
            severity: Severity::Medium,
            location: Location {
                path: "leak.txt".to_string(),
                line: 1,
                column: 9,
                snippet: snippet.to_string(),
            },
            message: "synthetic secret token detected".to_string(),
            evidence: "[REDACTED]".to_string(),
        }
    }

    #[test]
    fn request_body_is_bounded() {
        // Count budget: 50 findings travel as the first 20, in order.
        let many: Vec<Finding> = (0..50)
            .map(|n| finding(&format!("id-{n:02}"), "[REDACTED]"))
            .collect();
        let value: serde_json::Value = serde_json::from_str(&HttpExplainer::body(&many)).unwrap();
        let ids: Vec<&str> = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), MAX_FINDINGS);
        assert_eq!((ids[0], ids[19]), ("id-00", "id-19"));
        // Byte budget: oversized context truncates to a fitting prefix.
        let big: Vec<Finding> = (0..5)
            .map(|n| finding(&format!("id-{n}"), &"x".repeat(1200)))
            .collect();
        let value: serde_json::Value = serde_json::from_str(&HttpExplainer::body(&big)).unwrap();
        let items = value["findings"].as_array().unwrap();
        assert!(
            !items.is_empty() && items.len() < 5,
            "a fitting prefix travels"
        );
        assert_eq!(items[0]["id"].as_str().unwrap(), "id-0");
        let context: usize = items.iter().map(|entry| entry.to_string().len()).sum();
        assert!(context <= MAX_CONTEXT_BYTES, "context: {context}");
        assert!(HttpExplainer::body(&[]).contains("[]"));
    }

    #[test]
    fn envelope_parses_and_rejects() {
        let parsed = HttpExplainer::parse(r#"[{"id": "a", "text": "ok"}]"#).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].finding_id, "a");
        assert_eq!(parsed[0].text, "ok");
        for bad in [
            "not json",
            "{}",
            "[1]",
            r#"[{"id": 1, "text": "x"}]"#,
            r#"[{"id": "a"}]"#,
        ] {
            assert!(HttpExplainer::parse(bad).is_err(), "body {bad:?}");
        }
    }

    #[test]
    fn non_https_urls_refused_outside_loopback() {
        assert!(HttpExplainer::maybe_new("https://example.com/x", "k").is_some());
        assert!(HttpExplainer::maybe_new("http://127.0.0.1:9/x", "k").is_some());
        assert!(HttpExplainer::maybe_new("http://localhost:9/x", "k").is_some());
        for bad in [
            "http://example.com/x",
            "http://localhost.evil.com/x",
            "ftp://example.com/x",
            "",
        ] {
            assert!(HttpExplainer::maybe_new(bad, "k").is_none(), "url {bad:?}");
        }
        assert!(HttpExplainer::maybe_new("https://example.com/x", "").is_none());
    }

    #[test]
    fn userinfo_urls_are_refused_on_every_scheme() {
        // The host must be validated as a host, never as a substring of
        // the authority: the userinfo prefix below looks loopback while
        // the real host is not.
        for evil in [
            "http://127.0.0.1:9@192.168.1.240:38111/explain",
            "http://localhost:9@192.168.1.240:38111/explain",
            "http://127.0.0.1:9@127.0.0.1:38111/explain",
            "http://localhost:9@localhost:38111/explain",
            "https://user@example.com/x",
            "https://user:pass@example.com/x",
            "http://user@127.0.0.1:38111/explain",
        ] {
            assert!(
                HttpExplainer::maybe_new(evil, "k").is_none(),
                "userinfo url accepted: {evil:?}"
            );
        }
    }

    #[test]
    fn bracketed_ipv6_loopback_is_allowed() {
        assert!(HttpExplainer::maybe_new("http://[::1]:9/x", "k").is_some());
        assert!(HttpExplainer::maybe_new("http://[::1]/x", "k").is_some());
        // An unbracketed or non-loopback IPv6 literal stays refused.
        for bad in ["http://[::2]:9/x", "http://::1:9/x", "http://[]:9/x"] {
            assert!(HttpExplainer::maybe_new(bad, "k").is_none(), "url {bad:?}");
        }
    }

    #[test]
    fn serialized_body_never_exceeds_the_byte_cap() {
        // The cap covers what leaves the process: entries, commas, and
        // the envelope. A sweep hits every remainder, so any accounting
        // that forgets the envelope overflows for some snippet length.
        for len in (0..5000).step_by(13) {
            let found = vec![finding("id-0", &"x".repeat(len))];
            let body = HttpExplainer::body(&found);
            assert!(
                body.len() <= MAX_CONTEXT_BYTES,
                "snippet len {len}: on-wire body is {} bytes",
                body.len()
            );
        }
    }

    #[test]
    fn default_timeout_is_ten_seconds() {
        let explainer = HttpExplainer::maybe_new("https://example.com/x", "k").unwrap();
        assert_eq!(explainer.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn refused_connection_is_a_single_failed_attempt() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url = format!("http://127.0.0.1:{port}/explain");
        let explainer = HttpExplainer::maybe_new(&url, "k").unwrap();
        let result = explainer.explain(&[finding("id-0", "[REDACTED]")]);
        assert!(matches!(result, Err(ExplainError::Failed(_))));
    }

    #[test]
    fn stalled_endpoint_fails_fast_with_injected_timeout() {
        use std::io::{Read, Write};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Instant;
        // Why: `with_timeout` is the evidence hook for the 10-second bound;
        // a stalling loopback proves the timeout fires on the same code path
        // without spending ten seconds per suite run.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/explain");
        let count = Arc::new(AtomicUsize::new(0));
        let kept = Arc::clone(&count);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
                    let Ok(1) = stream.read(&mut byte) else { break };
                    head.push(byte[0]);
                }
                kept.fetch_add(1, Ordering::SeqCst);
                // Stall past the injected timeout without replying.
                std::thread::sleep(Duration::from_secs(5));
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
                );
            }
        });
        let explainer = HttpExplainer::with_timeout(&url, "k", Duration::from_millis(100)).unwrap();
        assert_eq!(explainer.timeout(), Duration::from_millis(100));
        let started = Instant::now();
        let result = explainer.explain(&[finding("id-0", "[REDACTED]")]);
        let elapsed = started.elapsed();
        assert!(
            matches!(result, Err(ExplainError::Failed(_))),
            "a stall maps to explain-failed: {result:?}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "timeouts are never retried"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the injected timeout fires fast: {elapsed:?}"
        );
    }
}

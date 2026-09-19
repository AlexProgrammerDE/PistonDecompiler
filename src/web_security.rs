use anyhow::{Result, ensure};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[derive(Clone)]
pub(crate) struct BrowserPolicy {
    authorities: Vec<String>,
    origins: Vec<String>,
}
impl BrowserPolicy {
    pub(crate) fn new(addr: SocketAddr, extra_origins: &[String]) -> Result<Self> {
        let authorities = vec![addr.to_string(), format!("localhost:{}", addr.port())];
        let mut origins: Vec<_> = authorities.iter().map(|a| format!("http://{a}")).collect();
        for origin in extra_origins {
            let uri: Uri = origin.parse()?;
            ensure!(
                matches!(uri.scheme_str(), Some("http" | "https"))
                    && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
                    && uri.path() == "/"
                    && uri.query().is_none()
                    && origin
                        == &format!(
                            "{}://{}",
                            uri.scheme_str().unwrap(),
                            uri.authority().unwrap()
                        ),
                "browser_origins must contain exact HTTP origins without paths"
            );
            origins.push(origin.clone());
        }
        Ok(Self {
            authorities,
            origins,
        })
    }

    fn permits(&self, request: &Request) -> bool {
        let headers = request.headers();
        // HTTP/2 uses :authority. Reject conflicting or repeated HTTP/1 Host values.
        let host = single_header(headers, header::HOST.as_str());
        let authority = request.uri().authority().map(|a| a.as_str());
        let Some(target) = authority.or(host) else {
            return false;
        };
        if !self.authorities.iter().any(|a| a == target)
            || (headers.contains_key(header::HOST) && host.is_none())
            || headers.get_all(header::HOST).iter().count() > 1
            || matches!((authority, host), (Some(a), Some(h)) if a != h)
        {
            return false;
        }
        if headers.contains_key(header::ORIGIN) {
            return single_header(headers, header::ORIGIN.as_str())
                .is_some_and(|origin| self.origins.iter().any(|allowed| allowed == origin));
        }
        // Browser requests without Origin still carry Fetch Metadata. Native clients
        // can omit both; these checks isolate websites, not other local processes.
        !headers.contains_key("sec-fetch-site")
            || matches!(
                single_header(headers, "sec-fetch-site"),
                Some("same-origin" | "none")
            )
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

pub(crate) async fn guard(
    State(policy): State<BrowserPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.permits(&request) {
        return (
            StatusCode::FORBIDDEN,
            "Request host or browser origin is not allowed",
        )
            .into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    response
}

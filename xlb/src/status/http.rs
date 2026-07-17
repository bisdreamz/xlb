use super::StatusState;
use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use log::info;
use rust_embed::RustEmbed;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(RustEmbed)]
#[folder = "../admin-ui/dist/"]
struct AdminUi;

const UI_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

pub struct AdminServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    exited: Option<oneshot::Receiver<Result<()>>>,
    task: JoinHandle<()>,
}

impl AdminServerHandle {
    /// Waits for an exit that occurs before shutdown was requested. Any such
    /// exit is fatal because it removes XLB's liveness and readiness surface.
    pub async fn wait_for_unexpected_exit(&mut self) -> Result<()> {
        let result = self
            .exited
            .as_mut()
            .ok_or_else(|| anyhow!("Admin HTTP server exit has already been observed"))?
            .await;
        self.exited.take();

        match result {
            Ok(Ok(())) => Err(anyhow!("Admin HTTP server stopped unexpectedly")),
            Ok(Err(error)) => Err(error).context("Admin HTTP server failed"),
            Err(_) => Err(anyhow!(
                "Admin HTTP server task ended without reporting its result"
            )),
        }
    }

    pub async fn shutdown(mut self, timeout: Duration) -> Result<()> {
        let shutdown_requested = self
            .shutdown
            .take()
            .is_some_and(|shutdown| shutdown.send(()).is_ok());
        match tokio::time::timeout(timeout, &mut self.task).await {
            Ok(result) => result.context("Admin HTTP server task failed")?,
            Err(_) => {
                self.task.abort();
                match self.task.await {
                    Ok(()) => {}
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => return Err(error).context("Admin HTTP server task failed"),
                }
                return Err(anyhow!(
                    "Admin HTTP server did not stop within {} ms",
                    timeout.as_millis()
                ));
            }
        }

        let Some(exited) = self.exited.take() else {
            return Ok(());
        };
        match exited.await {
            Ok(Ok(())) if shutdown_requested => Ok(()),
            Ok(Ok(())) => Err(anyhow!("Admin HTTP server stopped before shutdown")),
            Ok(Err(error)) => Err(error).context("Admin HTTP server failed"),
            Err(_) => Err(anyhow!(
                "Admin HTTP server task ended without reporting its result"
            )),
        }
    }
}

pub async fn start_admin_server(
    listen: SocketAddr,
    status: Arc<StatusState>,
) -> Result<AdminServerHandle> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("Failed to bind admin HTTP server to {listen}"))?;
    let local_addr = listener
        .local_addr()
        .context("Failed to read admin HTTP server address")?;
    let app = router(status);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (exit_tx, exit_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .context("Admin HTTP server stopped while serving requests");
        let _ = exit_tx.send(result);
    });

    info!("Admin HTTP server listening on http://{local_addr} (UI: /admin/)");
    Ok(AdminServerHandle {
        shutdown: Some(shutdown_tx),
        exited: Some(exit_rx),
        task,
    })
}

fn router(status: Arc<StatusState>) -> Router {
    Router::new()
        .route("/", get(admin_redirect))
        .route("/admin", get(admin_redirect))
        .route("/admin/", get(admin_index))
        .route("/admin/{*path}", get(admin_asset))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/status", get(api_status))
        .with_state(status)
}

async fn admin_redirect() -> Redirect {
    Redirect::permanent("/admin/")
}

async fn admin_index() -> Response {
    ui_asset_response("index.html").unwrap_or_else(ui_unavailable_response)
}

async fn admin_asset(Path(path): Path<String>) -> Response {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return admin_index().await;
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == ".." || segment.starts_with('.'))
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(response) = ui_asset_response(path) {
        return response;
    }

    // Vue Router owns extensionless routes. Missing files must remain a 404 so
    // a broken deployment cannot accidentally return HTML as JavaScript/CSS.
    if !path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.contains('.'))
    {
        return admin_index().await;
    }

    StatusCode::NOT_FOUND.into_response()
}

fn ui_asset_response(path: &str) -> Option<Response> {
    let asset = AdminUi::get(path)?;
    let body = match asset.data {
        Cow::Borrowed(bytes) => Body::from(bytes),
        Cow::Owned(bytes) => Body::from(bytes),
    };
    let cache_control = if path == "index.html" {
        "no-store"
    } else if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };

    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type(path))
            .header(header::CACHE_CONTROL, cache_control)
            .header("content-security-policy", UI_CONTENT_SECURITY_POLICY)
            .header("referrer-policy", "no-referrer")
            .header("x-content-type-options", "nosniff")
            .header("x-frame-options", "DENY")
            .body(body)
            .expect("valid embedded UI response"),
    )
}

fn ui_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "XLB admin UI was not built into this binary. Run `npm ci --prefix admin-ui`, `npm run build --prefix admin-ui`, then rebuild XLB.\n",
    )
        .into_response()
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") | Some("map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn healthz(State(status): State<Arc<StatusState>>) -> Response {
    let health = status.health();
    let status_code = if health.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    text_response(status_code, health.reason.as_str())
}

async fn readyz(State(status): State<Arc<StatusState>>) -> Response {
    let readiness = status.readiness();
    let status_code = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    text_response(status_code, readiness.reason.as_str())
}

async fn api_status(State(status): State<Arc<StatusState>>) -> Response {
    let mut response = Json(status.snapshot()).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn text_response(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        format!("{body}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{PortStatus, ProviderKind, ReadinessReason, StatusMetadata, StatusState};
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    fn state() -> Arc<StatusState> {
        Arc::new(StatusState::new(StatusMetadata {
            service: "test-lb".into(),
            provider: ProviderKind::Static,
            listen_address: "192.0.2.1".parse().expect("valid IP"),
            listen_interface: "eth0".into(),
            attached_interfaces: vec!["eth0".into()],
            protocol: xlb_common::net::Proto::Tcp,
            routing_mode: xlb_common::config::routing::RoutingMode::Nat,
            ports: vec![PortStatus {
                listen: 80,
                backend: 8080,
            }],
        }))
    }

    async fn body(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        String::from_utf8(bytes.to_vec()).expect("UTF-8 response")
    }

    async fn request(app: Router, uri: &str) -> Response {
        app.oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("admin response")
    }

    #[tokio::test]
    async fn health_is_live_while_readiness_reports_starting() {
        let health = healthz(State(state())).await;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(body(health).await, "starting\n");

        let ready = readyz(State(state())).await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body(ready).await, "starting\n");
    }

    #[tokio::test]
    async fn status_api_is_json_and_not_cacheable() {
        let response = api_status(State(state())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );

        let value: serde_json::Value =
            serde_json::from_str(&body(response).await).expect("valid status JSON");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["readiness"]["reason"], "starting");
        assert_eq!(value["dataplane"]["protocol"], "tcp");
        assert_eq!(value["dataplane"]["routing_mode"], "nat");
        assert_eq!(
            ReadinessReason::Starting.as_str(),
            value["readiness"]["reason"]
        );
    }

    #[tokio::test]
    async fn router_exposes_only_the_versioned_status_path() {
        let app = router(state());
        let status_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("status response");
        let old_path_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("not-found response");

        assert_eq!(status_response.status(), StatusCode::OK);
        assert_eq!(old_path_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_ui_redirects_and_serves_spa_routes_safely() {
        let app = router(state());
        let redirect = request(app.clone(), "/").await;
        assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            redirect.headers().get(header::LOCATION),
            Some(&HeaderValue::from_static("/admin/"))
        );

        let index = request(app.clone(), "/admin/").await;
        if AdminUi::get("index.html").is_none() {
            assert_eq!(index.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(body(index).await.contains("admin UI was not built"));
            return;
        }

        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/html; charset=utf-8"))
        );
        assert_eq!(
            index.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(index.headers().contains_key("content-security-policy"));
        assert!(body(index).await.contains("<div id=\"app\"></div>"));

        let history_route = request(app.clone(), "/admin/backends").await;
        assert_eq!(history_route.status(), StatusCode::OK);
        assert!(body(history_route).await.contains("<div id=\"app\"></div>"));

        let javascript = AdminUi::iter()
            .find(|path| path.ends_with(".js"))
            .expect("built UI contains JavaScript")
            .into_owned();
        let asset = request(app.clone(), &format!("/admin/{javascript}")).await;
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "public, max-age=31536000, immutable"
            ))
        );
        assert_eq!(
            asset.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/javascript; charset=utf-8"))
        );

        let missing_asset = request(app, "/admin/assets/missing.js").await;
        assert_eq!(missing_asset.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn admin_ui_content_types_do_not_depend_on_browser_sniffing() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("assets/app.css"), "text/css; charset=utf-8");
        assert_eq!(
            content_type("assets/app.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type("favicon.svg"), "image/svg+xml");
        assert_eq!(content_type("unknown.bin"), "application/octet-stream");
    }

    #[tokio::test]
    async fn server_exit_before_shutdown_is_fatal() {
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let (exit_tx, exit_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = exit_tx.send(Ok(()));
        });
        let mut handle = AdminServerHandle {
            shutdown: Some(shutdown_tx),
            exited: Some(exit_rx),
            task,
        };

        let error = handle
            .wait_for_unexpected_exit()
            .await
            .expect_err("an unrequested server exit must stop XLB");
        assert!(error.to_string().contains("stopped unexpectedly"));
        handle
            .shutdown(Duration::from_secs(1))
            .await
            .expect("join server task");
    }

    #[tokio::test]
    async fn shutdown_aborts_a_server_that_exceeds_its_deadline() {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (exit_tx, exit_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _shutdown_rx = shutdown_rx;
            let _exit_tx = exit_tx;
            std::future::pending::<()>().await;
        });
        let handle = AdminServerHandle {
            shutdown: Some(shutdown_tx),
            exited: Some(exit_rx),
            task,
        };

        let error = handle
            .shutdown(Duration::from_millis(10))
            .await
            .expect_err("a stalled server must not block shutdown indefinitely");
        assert!(error.to_string().contains("did not stop within 10 ms"));
    }

    #[tokio::test]
    async fn requested_shutdown_waits_for_a_successful_server_exit() {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (exit_tx, exit_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            shutdown_rx.await.expect("receive shutdown request");
            let _ = exit_tx.send(Ok(()));
        });
        let handle = AdminServerHandle {
            shutdown: Some(shutdown_tx),
            exited: Some(exit_rx),
            task,
        };

        handle
            .shutdown(Duration::from_secs(1))
            .await
            .expect("requested server shutdown succeeds");
    }
}

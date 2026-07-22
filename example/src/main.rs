use axum::http::StatusCode;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_status::SetStatus,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // `ServeDir` serves the files in the "assets" directory, falling back to
    // `index.html` (with a 404 status) for any path that doesn't match a file.
    let index_html = SetStatus::new(ServeFile::new("assets/index.html"), StatusCode::NOT_FOUND);
    let serve_dir = ServeDir::new("assets").not_found_service(index_html);

    let app = axum::Router::new()
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

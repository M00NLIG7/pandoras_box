pub mod types;

use actix_web::dev::Server;
use actix_web::dev::ServerHandle;
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde_json::json;
use std::sync::{Arc, Mutex};
use types::ServerNode;

#[post("/evil_fetch")]
pub async fn evil_fetch(
    highest_node: web::Data<Arc<Mutex<ServerNode>>>,
    new_node: web::Json<ServerNode>,
) -> impl Responder {
    if let Ok(mut highest_node) = highest_node.lock() {
        if new_node.evil_secret > highest_node.evil_secret {
            *highest_node = new_node.into_inner();
            HttpResponse::Ok().json(json!({"message": "New highest node!"}))
        } else {
            HttpResponse::Ok().json(json!({"message": "Not the highest node."}))
        }
    } else {
        // Handle lock error, maybe return an internal server error
        HttpResponse::InternalServerError().body("Failed to acquire lock")
    }
}

// Function to run the server
pub async fn start_server(server_node: Arc<Mutex<ServerNode>>) -> (Server, ServerHandle) {
    let srv = HttpServer::new(move || {
        App::new()
            // Add the shared state to the app
            .app_data(web::Data::new(server_node.clone()))
            .service(evil_fetch)
        // Define the route and associate it with the handler function
        // .route("/evil_fetch", web::post().to(evil_fetch))
    })
    // Bind the server to an address
    .bind("0.0.0.0:8080")
    .expect("Can not bind to port 8080")
    // Start the server
    .run();

    let srv_handle = srv.handle();
    return (srv, srv_handle);
}

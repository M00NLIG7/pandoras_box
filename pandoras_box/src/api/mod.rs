pub mod types;

use actix_web::dev::Server;
use actix_web::dev::ServerHandle;
use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use types::{RootNode, ServerNode};

#[post("/evil_fetch")]
pub async fn evil_fetch(
    req: HttpRequest, // Include the HttpRequest object in the parameters
    highest_node: web::Data<Arc<Mutex<ServerNode>>>,
    new_node: web::Json<ServerNode>,
) -> impl Responder {
    let connection_info = req.connection_info();
    let client_ip = connection_info.peer_addr().unwrap_or("0.0.0.0");

    if let Ok(mut highest_node) = highest_node.lock() {
        if new_node.evil_secret > highest_node.evil_secret {
            *highest_node = new_node.into_inner();
            println!("Client IP: {}", client_ip);
            println!("New highest node: {:?}", highest_node);
            HttpResponse::Ok().json(json!({"message": "New highest node!"}))
        } else {
            HttpResponse::Ok().json(json!({"message": "Not the highest node."}))
        }
    } else {
        // Handle lock error, maybe return an internal server error
        HttpResponse::InternalServerError().body("Failed to acquire lock")
    }
}

#[post("/root")]
pub async fn root(
    req: HttpRequest, // To access the request headers
    api_key_sender: web::Data<Arc<watch::Sender<String>>>, // Shared storage for the API key
) -> impl Responder {
    println!("Incoming Request: {} {}", req.method(), req.uri());
    for (header, value) in req.headers() {
        println!(
            "Header: {} - Value: {}",
            header,
            value.to_str().unwrap_or("[Invalid UTF-8]")
        );
    }
    if let Some(api_key) = req.headers().get("x-api-key").and_then(|v| v.to_str().ok()) {
        let _ = api_key_sender.send(api_key.to_string());
        HttpResponse::Ok().json(json!({"message": "API key updated"}))
    } else {
        HttpResponse::BadRequest().body("Missing API key")
    }
}

// Function to run the server
pub async fn start_server(
    shared_api_key: Arc<watch::Sender<String>>,
    server_node: Arc<Mutex<ServerNode>>,
) -> (Server, ServerHandle) {
    let srv = HttpServer::new(move || {
        App::new()
            // Add the shared state to the app
            .app_data(web::Data::new(shared_api_key.clone()))
            .app_data(web::Data::new(server_node.clone()))
            .service(evil_fetch)
            .service(root)
        // Define the route and associate it with the handler function
        // .route("/evil_fetch", web::post().to(evil_fetch))
    })
    // Bind the server to an address
    .bind("0.0.0.0:6969")
    .expect("Can not bind to port 6969")
    // Start the server
    .run();

    let srv_handle = srv.handle();
    return (srv, srv_handle);
}

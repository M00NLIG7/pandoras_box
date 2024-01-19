pub mod types;
use actix_web::dev::Server;
use actix_web::dev::ServerHandle;
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde_json::json;
use std::collections::BinaryHeap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use types::{RootNode, ServerNode};

#[post("/evil_fetch")]
pub async fn evil_fetch(
    req: HttpRequest,
    heap: web::Data<Arc<Mutex<BinaryHeap<ServerNode>>>>,
    new_node: web::Json<ServerNode>,
) -> impl Responder {
    let connection_info = req.connection_info();
    let client_ip = connection_info.peer_addr().unwrap_or("0.0.0.0");
    let mut heap = heap.lock().unwrap();

    heap.push(new_node.into_inner());
    println!("Client IP: {}", client_ip);
    println!("New node added. Current highest node: {:?}", heap.peek());

    HttpResponse::Ok().json(json!({"message": "Node added"}))
}

#[get("/chimera")]
async fn chimera(chimera: web::Data<Arc<Vec<u8>>>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(chimera.to_vec())
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

pub async fn start_server(
    shared_api_key: Arc<watch::Sender<String>>,
    server_heap: Arc<Mutex<BinaryHeap<ServerNode>>>, // Added this parameter
    chimera_bin: Arc<Vec<u8>>,
) -> (Server, ServerHandle) {
    let srv = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(chimera_bin.clone()))
            .app_data(web::Data::new(shared_api_key.clone()))
            .app_data(web::Data::new(server_heap.clone())) // Use the passed heap
            .service(evil_fetch)
            .service(root)
            .service(chimera)
        // other configurations
    })
    .bind("0.0.0.0:6969")
    .expect("Can not bind to port 6969")
    .run();

    let srv_handle = srv.handle();
    return (srv, srv_handle);
}

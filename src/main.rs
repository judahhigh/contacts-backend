use actix_web::{ middleware, web, App, HttpServer, http };
use actix_cors::Cors;
use std::sync::Arc;
use std::env;
use dotenv::dotenv;

#[allow(warnings, unused)]
mod prisma;
use prisma::PrismaClient;

use biscuit_auth::KeyPair;

mod users;
mod utils;
mod contacts;
mod login;

use crate::users::{ update_user, get_user, delete_user, create_user };
use crate::contacts::{
    get_contact,
    get_all_contacts,
    create_contact,
    update_contact,
    delete_contact,
    delete_all_contacts,
};
use crate::login::{login as login_handler, register};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let host = env::var("HOST").expect("The host name should exist.");
    let allowed_origin = env::var("ALLOWED_ORIGIN").expect("The allowed origin should exist.");

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let client = Arc::new(PrismaClient::_builder().build().await.unwrap());

    log::info!("Starting HTTP server at http://{}", host);

    // Used for biscuit auth
    let root_keypair = Arc::new(KeyPair::new());

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(allowed_origin.as_str())
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().ends_with(b".rust-lang.org")
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(client.clone()))
            .app_data(web::Data::new(root_keypair.clone()))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .service(create_user)
            .service(get_user)
            .service(update_user)
            .service(delete_user)
            .service(create_contact)
            .service(get_contact)
            .service(get_all_contacts)
            .service(update_contact)
            .service(delete_contact)
            .service(delete_all_contacts)
            .service(login_handler)
            .service(register)
    })
        .bind(host)?
        .run().await
}

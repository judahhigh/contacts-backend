use actix_web::{
    get,
    post,
    put,
    delete,
    middleware,
    web,
    App,
    HttpResponse,
    HttpServer,
    Responder,
    HttpRequest,
    http,
};
use actix_cors::Cors;
use std::sync::Arc;
use serde::Deserialize;
use std::env;
use dotenv::dotenv;
use bcrypt::{ DEFAULT_COST, hash, verify };

#[allow(warnings, unused)]
mod prisma;
use prisma::PrismaClient;
use prisma::user;

fn is_authed(req: HttpRequest) -> bool {
    match req.headers().get("Authorization") {
        Some(auth_header) => {
            log::info!("auth_header");
            let auth_header = String::from(auth_header.to_str().unwrap());
            match env::var("AUTH_KEY") {
                Ok(auth_key) => auth_header.eq(&auth_key),
                Err(_) => false,
            }
        }
        None => { false }
    }
}

#[get("/users/{user_id}")]
async fn get_user(
    client: web::Data<Arc<PrismaClient>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id = path.into_inner();
    match
        client
            .user()
            .find_first(vec![user::id::equals(user_id)])
            .exec().await
            .unwrap()
    {
        Some(user_data) => HttpResponse::Ok().content_type("application/json").json(user_data),
        None => HttpResponse::NotFound().finish(),
    }
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    password: String,
}

#[post("/users")]
async fn create_user(
    client: web::Data<Arc<PrismaClient>>,
    body: web::Json<CreateUserRequest>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    match
        client
            .user()
            .find_unique(user::username::equals(body.username.clone()))
            .exec().await
            .unwrap()
    {
        Some(_) => {
            return HttpResponse::BadRequest().finish();
        }
        None => (), //User doesn't exist, we can add it
    }

    // encrypt and salt password
    match hash(body.password.clone(), DEFAULT_COST) {
        Ok(hashed_password) => {
            match verify(body.password.clone(), &hashed_password) {
                Ok(verified) => {
                    if !verified {
                        return HttpResponse::InternalServerError().finish();
                    }

                    let user = client
                        .user()
                        .create(
                            body.username.to_string(),
                            body.email.to_string(),
                            hashed_password.to_string(),
                            vec![]
                        )
                        .exec().await
                        .unwrap();

                    HttpResponse::Ok().json(user)
                }
                Err(_error) => { HttpResponse::InternalServerError().finish() }
            }
        }
        Err(_error) => { HttpResponse::InternalServerError().finish() }
    }
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    id: String,
    username: String,
    email: String,
    password: String,
}

#[put("/users")]
async fn update_user(
    client: web::Data<Arc<PrismaClient>>,
    body: web::Json<UpdateUserRequest>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    // Make sure the user exists so we can update it
    match client.user().find_unique(user::id::equals(body.id.clone())).exec().await.unwrap() {
        Some(_) => (), // User exists, so we can update it,
        None => {
            return HttpResponse::BadRequest().finish();
        } // User doesn't exist, should only create with post endpoint
    }

    // In case the client changed the password, hash the new password
    let hash_result = hash(body.password.clone(), DEFAULT_COST);
    if hash_result.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    let hashed_password = hash_result.unwrap();
    let valid = verify(body.password.clone(), &hashed_password);
    if valid.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    if !valid.unwrap() {
        return HttpResponse::InternalServerError().finish();
    }

    // Update the client's user data
    let user = client
        .user()
        .update(
            user::id::equals(body.id.to_string()),
            vec![
                user::username::set(body.username.to_string()),
                user::email::set(body.email.to_string()),
                user::password::set(hashed_password.to_string())
            ]
        )
        .exec().await
        .unwrap();

    HttpResponse::Ok().json(user)
}

#[delete("/users/{user_id}")]
async fn delete_user(
    client: web::Data<Arc<PrismaClient>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id: String = path.into_inner();
    match client.user().find_unique(user::id::equals(user_id.clone())).exec().await.unwrap() {
        Some(_) => (), // User exists, so we can delete it,
        None => {
            return HttpResponse::BadRequest().finish();
        } // User doesn't exist, should only create with post endpoint
    }

    let user = client.user().delete(user::id::equals(user_id)).exec().await.unwrap();
    HttpResponse::Ok().json(user)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let host = env::var("HOST").expect("The host name should exist.");
    let allowed_origin = env::var("ALLOWED_ORIGIN").expect("The allowed origin should exist.");

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let client = Arc::new(PrismaClient::_builder().build().await.unwrap());

    log::info!("Starting HTTP server at http://{}", host);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(allowed_origin.as_str())
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().ends_with(b".rust-lang.org")
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(client.clone()))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .service(create_user)
            .service(get_user)
            .service(update_user)
            .service(delete_user)
    })
        .bind(host)?
        .run().await
}

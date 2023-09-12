use actix_web::{ get, post, put, delete, web, HttpResponse, Responder, HttpRequest };
use std::sync::Arc;
use serde::Deserialize;
use bcrypt::{ DEFAULT_COST, hash, verify };

#[allow(warnings, unused)]
use crate::prisma::PrismaClient;
use crate::prisma::user;

use biscuit_auth::KeyPair;

use crate::utils::is_biscuit_authed;

#[get("/users/{user_id}")]
async fn get_user(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
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
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<CreateUserRequest>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
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
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<UpdateUserRequest>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
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
    root_key_pair: web::Data<Arc<KeyPair>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
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

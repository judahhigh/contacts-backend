use actix_web::{ get, post, web, HttpResponse, Responder, HttpRequest };
use std::sync::Arc;
use serde::Deserialize;

#[allow(warnings, unused)]
use crate::prisma::PrismaClient;
use crate::prisma::{ user, contact };

use crate::utils::is_authed;

#[derive(Deserialize)]
struct CreateContactRequest {
    first_name: String,
    last_name: String,
    email: String,
    tel: String,
}

#[post("/users/{user_id}/contacts")]
async fn create_contact(
    client: web::Data<Arc<PrismaClient>>,
    body: web::Json<CreateContactRequest>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id: String = path.into_inner();
    log::info!("{}", user_id);
    let user = client
        .contact()
        .create(
            body.first_name.to_string(),
            body.last_name.to_string(),
            body.email.to_string(),
            body.tel.to_string(),
            user::id::equals(user_id.to_string()),
            vec![]
        )
        .exec().await
        .unwrap();

    HttpResponse::Ok().json(user)
}

#[get("/users/{user_id}/contacts/{contact_id}")]
async fn get_contact(
    client: web::Data<Arc<PrismaClient>>,
    path: web::Path<(String, String)>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    let (user_id, contact_id) = path.into_inner();
    match
        client
            .contact()
            .find_first(vec![contact::id::equals(contact_id), contact::user_id::equals(user_id)])
            .exec().await
            .unwrap()
    {
        Some(user_data) => HttpResponse::Ok().content_type("application/json").json(user_data),
        None => HttpResponse::NotFound().finish(),
    }
}

#[get("/users/{user_id}/contacts")]
async fn get_all_contacts(
    client: web::Data<Arc<PrismaClient>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_authed(req) {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id = path.into_inner();
    let data = client
        .contact()
        .find_many(vec![contact::user_id::equals(user_id.to_string())])
        .exec().await
        .unwrap();
    HttpResponse::Ok().content_type("application/json").json(data)
}

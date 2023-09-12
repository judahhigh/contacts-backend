use actix_web::{ get, post, put, delete, web, HttpResponse, Responder, HttpRequest };
use std::sync::Arc;
use serde::Deserialize;

use biscuit_auth::KeyPair;

#[allow(warnings, unused)]
use crate::prisma::PrismaClient;
use crate::prisma::{ user, contact };

use crate::utils::is_biscuit_authed;

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
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<CreateContactRequest>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id: String = path.into_inner();
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
    root_key_pair: web::Data<Arc<KeyPair>>,
    path: web::Path<(String, String)>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
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
    root_key_pair: web::Data<Arc<KeyPair>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
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

#[derive(Deserialize)]
struct UpdateContactRequest {
    id: String,
    first_name: String,
    last_name: String,
    email: String,
    tel: String,
}

#[put("/users/{user_id}/contacts")]
async fn update_contact(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<UpdateContactRequest>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
        return HttpResponse::Unauthorized().finish();
    }

    let user_id = path.into_inner();
    let contact_id = body.id.clone();

    // First check that the specified contact belongs to the user specified
    let res = client
        .contact()
        .find_unique(contact::id::equals(contact_id.clone()))
        .exec().await
        .unwrap();
    if res.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let contact = res.unwrap();
    if contact.user_id != user_id {
        return HttpResponse::BadRequest().finish();
    }

    let updated_contact = client
        .contact()
        .update(
            contact::id::equals(contact_id),
            vec![
                contact::first_name::set(body.first_name.to_string()),
                contact::last_name::set(body.last_name.to_string()),
                contact::email::set(body.email.to_string()),
                contact::tel::set(body.tel.to_string())
            ]
        )
        .exec().await
        .unwrap();

    HttpResponse::Ok().json(updated_contact)
}

#[delete("/users/{user_id}/contacts/{contact_id}")]
async fn delete_contact(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    path: web::Path<(String, String)>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
        return HttpResponse::Unauthorized().finish();
    }

    let (user_id, contact_id) = path.into_inner();

    match
        client.contact().find_unique(contact::id::equals(contact_id.clone())).exec().await.unwrap()
    {
        Some(contact) => {
            // Found a matching contact, but let's make sure it's associated with the right user
            if contact.user_id != user_id {
                return HttpResponse::BadRequest().finish();
            }
        }
        None => {
            return HttpResponse::BadRequest().finish();
        } // User doesn't exist, should only create with post endpoint
    }

    let deleted_contact = client
        .contact()
        .delete(contact::id::equals(contact_id))
        .exec().await
        .unwrap();
    HttpResponse::Ok().json(deleted_contact)
}

#[delete("/users/{user_id}/contacts")]
async fn delete_all_contacts(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    path: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    if !is_biscuit_authed(req, root_key_pair) {
        return HttpResponse::Unauthorized().finish();
    }
    let user_id = path.into_inner();
    let deleted_contacts = client
        .contact()
        .delete_many(vec![contact::user_id::equals(user_id)])
        .exec().await
        .unwrap();
    HttpResponse::Ok().json(deleted_contacts)
}

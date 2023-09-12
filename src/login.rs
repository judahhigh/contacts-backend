use actix_web::{ post, web, Responder, HttpResponse, cookie::Cookie, http::header::ContentType };
use std::sync::Arc;
use serde::Deserialize;
use bcrypt::{ hash, verify, DEFAULT_COST };
use std::time::{ SystemTime, Duration };

#[allow(warnings, unused)]
use crate::prisma::PrismaClient;
use crate::prisma::user;

use biscuit_auth::{ macros::*, KeyPair };

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[post("/login")]
async fn login(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<LoginRequest>
) -> impl Responder {
    // Verify the login attempt first
    let user = client
        .user()
        .find_unique(user::username::equals(body.username.to_string()))
        .exec().await
        .unwrap();
    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let user = user.unwrap();
    let stored_password = user.password;
    let password_attempt = body.password.clone();
    let password_verification = verify(password_attempt, &stored_password);
    if password_verification.is_err() {
        return HttpResponse::InternalServerError().finish();
    } else {
        let password_verification = password_verification.unwrap();
        if !password_verification {
            return HttpResponse::Unauthorized().finish();
        }
    }

    // Generate a Biscuit and give it back to the client
    // The biscuit is made to expire in 3600s or 60m
    let user_id = user.username.clone();
    let authority = biscuit!(
        r#"
            user({user_id});
            check if time($time), $time <= {expiration};
        "#,
        user_id = user_id,
        expiration = SystemTime::now() + Duration::from_secs(3600)
    );
    let token = authority.build(&root_key_pair).unwrap();
    HttpResponse::Ok().content_type(ContentType::plaintext()).insert_header(("Authorization", token.to_base64().unwrap())).finish()
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

#[post("/register")]
async fn register(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<RegisterRequest>
) -> impl Responder {
    // Check that a user with the provided username doesn't already exist
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

    // Create a new user
    let hashed_password = hash(body.password.to_string().clone(), DEFAULT_COST);
    if hashed_password.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    let hashed_password = hashed_password.unwrap();
    match verify(body.password.to_string(), &hashed_password) {
        Ok(verify) => {
            if !verify {
                return HttpResponse::InternalServerError().finish();
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().finish();
        }
    }
    let user = client
        .user()
        .create(body.username.to_string(), body.email.to_string(), hashed_password, vec![])
        .exec().await
        .unwrap();

    // Generate a Biscuit and give it back to the client
    // The biscuit is made to expire in 3600s or 60m
    let user_id = user.username.clone();
    let authority = biscuit!(
        r#"
            user({user_id});
            check if time($time), $time <= {expiration};
        "#,
        user_id = user_id,
        expiration = SystemTime::now() + Duration::from_secs(3600)
    );
    let token = authority.build(&root_key_pair).unwrap();

    HttpResponse::Ok().content_type("application/json").insert_header(("Authorization", token.to_base64().unwrap())).json(user)
}

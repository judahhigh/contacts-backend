use actix_web::{ get, post, web, Responder, HttpResponse, http::header::ContentType, HttpRequest };
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use bcrypt::{ hash, verify, DEFAULT_COST };
use std::time::{ SystemTime, Duration };

#[allow(warnings, unused)]
use crate::prisma::PrismaClient;
use crate::prisma::user;

use biscuit_auth::{ macros::*, Biscuit, KeyPair };

use crate::utils::is_biscuit_authed;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    user: user::Data,
    token: String,
}

#[post("/login")]
async fn login(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    body: web::Json<LoginRequest>
) -> impl Responder {
    println!("username: {:?}", body.username.to_string());
    println!("password: {:?}", body.password.to_string());
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
    let stored_password = user.password.clone();
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
    let user_id = user.id.clone();
    let authority = biscuit!(
        r#"
            user({user_id});
            check if time($time), $time <= {expiration};
        "#,
        user_id = user_id,
        expiration = SystemTime::now() + Duration::from_secs(3600)
    );
    let token = authority.build(&root_key_pair).unwrap();
    let response_body: LoginResponse = LoginResponse { user: user.clone(), token: token.to_base64().unwrap() };
    HttpResponse::Ok()
        .content_type("application/json")
        .json(response_body)
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    user: user::Data,
    token: String,
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
    
    let response_body: RegisterResponse = RegisterResponse { user: user.clone(), token: token.to_base64().unwrap() };
    HttpResponse::Ok()
        .content_type("application/json")
        .json(response_body)
}

#[derive(Serialize)]
struct RefreshResponse {
    user: user::Data,
    token: String,
}

#[get("/refresh")]
async fn refresh(
    client: web::Data<Arc<PrismaClient>>,
    root_key_pair: web::Data<Arc<KeyPair>>,
    req: HttpRequest
) -> impl Responder {
    // Validate the incoming authorization token before issuing a new token with a new expiration
    if !is_biscuit_authed(req.clone(), root_key_pair.clone()) {
        return HttpResponse::Unauthorized().finish();
    }

    let token = req.headers().get("Authorization");
    if token.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let token = String::from(token.unwrap().to_str().unwrap());
    let token = Biscuit::from_base64(&token, root_key_pair.public());
    if token.is_err() {
        return HttpResponse::Unauthorized().finish();
    }
    let token = token.unwrap();

    // According to how the biscuit is constructed, the zeroeth block should
    // only contain a single symbol for the username.
    let block_result = token.block_symbols(0);
    if block_result.is_err() {
        return HttpResponse::Unauthorized().finish();
    }
    let symbols = block_result.unwrap();
    if symbols.len() != 1 {
        return HttpResponse::Unauthorized().finish();
    }
    let user_id = symbols.first();
    if user_id.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let user_id = user_id.unwrap().clone();

    // Based on the username, let's attempt to get a matching user
    // from the database. We can't let any user get a refresh token
    // for any other user. The issuing user must only be able to
    // get a refresh token for themselves.
    let user = client.user().find_unique(user::id::equals(user_id)).exec().await.unwrap();
    if user.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let user = user.unwrap();

    // Generate a brand new shiny Biscuit and give it back to the client
    // The biscuit is made to expire in 3600s or 60m
    let user_id = user.id.clone();
    let authority = biscuit!(
        r#"
            user({user_id});
            check if time($time), $time <= {expiration};
        "#,
        user_id = user_id,
        expiration = SystemTime::now() + Duration::from_secs(3600)
    );
    let refresh_token = authority.build(&root_key_pair).unwrap();

    let response_body: RefreshResponse = RefreshResponse { user: user.clone(), token: refresh_token.to_base64().unwrap() };
    HttpResponse::Ok()
        .content_type("application/json")
        .json(response_body)
}

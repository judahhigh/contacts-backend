use actix_web::{ post, web, Responder, HttpResponse };
use std::sync::Arc;
use serde::Deserialize;
use bcrypt::verify;
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
    HttpResponse::Ok().content_type("application/json").body(token.to_base64().unwrap())
}

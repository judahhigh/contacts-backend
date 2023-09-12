use actix_web::HttpRequest;
use std::env;

pub fn is_authed(req: HttpRequest) -> bool {
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

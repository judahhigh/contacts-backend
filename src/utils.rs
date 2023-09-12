use actix_web::{ HttpRequest, web };
use std::sync::Arc;
use biscuit_auth::{ error, macros::*, Biscuit, KeyPair };

pub fn is_biscuit_authed(req: HttpRequest, root_key_pair: web::Data<Arc<KeyPair>>) -> bool {
    match req.headers().get("Authorization") {
        Some(auth_header) => {
            let auth_header = String::from(auth_header.to_str().unwrap());
            let token = Biscuit::from_base64(&auth_header, root_key_pair.public());
            if token.is_err() {
                return false;
            }
            let token = token.unwrap();
            let auth_res = authorize(&token);
            if auth_res.is_err() {
                false
            } else {
                true
            }
        }
        None => { false }
    }
}

fn authorize(token: &Biscuit) -> Result<(), error::Token> {
    let authorizer = authorizer!(r#"
        allow if user($u);
    "#);
    let res = token.authorize(&authorizer);
    if res.is_err() {
        return Err(res.err().unwrap());
    }
    Ok(())
}

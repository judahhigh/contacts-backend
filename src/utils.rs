use actix_web::{web, HttpRequest};
use biscuit_auth::{error, macros::*, Biscuit, KeyPair};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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
        None => false,
    }
}

pub fn authorize(token: &Biscuit) -> Result<(), error::Token> {
    let authorizer = authorizer!(
        r#"
            time({current_time});
            allow if user($u);
        "#,
        current_time = SystemTime::now()
    );
    let res = token.authorize(&authorizer);
    if res.is_err() {
        return Err(res.err().unwrap());
    }
    Ok(())
}

pub fn create_biscuit(keypair: Arc<KeyPair>, user_id: String) -> Result<Biscuit, ()> {
    let authority = biscuit!(
        r#"
            user({user_id});
            check if time($time), $time <= {expiration};
        "#,
        user_id = user_id,
        expiration = SystemTime::now() + Duration::from_secs(3600)
    );
    let token = authority.build(&keypair).unwrap();
    Ok(token)
}

use actix_web::{
    body::MessageBody,
    http::{header::ContentType, StatusCode},
    test, web, App,
};

use crate::prisma::user;
use crate::prisma::PrismaClient;
use crate::token::{login, refresh, register};
use crate::token::{
    LoginRequest, LoginResponse, RefreshResponse, RegisterRequest, RegisterResponse,
};
use crate::utils::{authorize, create_biscuit};
use bcrypt::{hash, verify, DEFAULT_COST};
use biscuit_auth::{error, macros::*, Biscuit, KeyPair};
use std::sync::Arc;
use uuid::Uuid;

mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_login_user_doesnt_exist() {
        let request_data: LoginRequest = LoginRequest {
            username: Uuid::new_v4().to_string(),
            password: Uuid::new_v4().to_string(),
        };

        let client = Arc::new(PrismaClient::_builder().build().await.unwrap());
        let root_keypair = Arc::new(KeyPair::new());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client.clone()))
                .app_data(web::Data::new(root_keypair.clone()))
                .service(login),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/login")
            .insert_header(ContentType::json())
            .set_json(request_data)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_login_user_exists() {
        // Set up a valid user and add it to the database and setup the request for login
        let username: String = Uuid::new_v4().to_string();
        let email: String = Uuid::new_v4().to_string();
        let password: String = Uuid::new_v4().to_string();
        let hashed_password = hash(password.to_string().clone(), DEFAULT_COST);
        assert!(hashed_password.is_ok());
        let hashed_password = hashed_password.unwrap();
        let client = Arc::new(PrismaClient::_builder().build().await.unwrap());
        let db_user = client
            .user()
            .create(username.clone(), email, hashed_password, vec![])
            .exec()
            .await
            .unwrap();
        let request_data: LoginRequest = LoginRequest {
            username: username.clone(),
            password: password.clone(),
        };

        // Create the app and call the request, deserialize the expected successful response
        let root_keypair = Arc::new(KeyPair::new());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client.clone()))
                .app_data(web::Data::new(root_keypair.clone()))
                .service(login),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/login")
            .insert_header(ContentType::json())
            .set_json(request_data)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Parse the response, validate the returned user info and token
        let body = resp.into_body();
        let bytes = body.try_into_bytes();
        assert!(bytes.is_ok());
        let json_string = String::from_utf8(bytes.unwrap().to_vec()).unwrap();
        let json = serde_json::from_str::<LoginResponse>(&json_string);
        assert!(json.is_ok());
        let login_response: LoginResponse = json.unwrap();
        assert_eq!(login_response.user.id, db_user.id);
        assert_eq!(login_response.user.username, db_user.username);
        assert_eq!(login_response.user.email, db_user.email);
        assert_eq!(login_response.user.password, db_user.password);
        assert!(login_response.user.contacts.is_none());
        let token = String::from(login_response.token.as_str());
        let token = Biscuit::from_base64(&token, root_keypair.public());
        assert!(token.is_ok());
        let token = token.unwrap();
        let auth_res = authorize(&token);
        assert!(auth_res.is_ok());

        // Now delete the user, thereby resetting the db
        match client
            .user()
            .delete(user::id::equals(db_user.id))
            .exec()
            .await
        {
            Ok(user_data) => {
                match client
                    .user()
                    .find_unique(user::id::equals(user_data.id))
                    .exec()
                    .await
                {
                    Ok(_) => assert!(true),
                    Err(_) => assert!(false),
                }
            }
            Err(_) => assert!(false),
        }
    }

    #[actix_web::test]
    async fn test_register_user_doesnt_exist() {
        // Set up a valid request
        let username: String = Uuid::new_v4().to_string();
        let email: String = Uuid::new_v4().to_string();
        let password: String = Uuid::new_v4().to_string();
        let request_data: RegisterRequest = RegisterRequest {
            username: username.clone(),
            email: email.clone(),
            password: password.clone(),
        };

        // Create the app and call the request, deserialize the expected successful response
        let client = Arc::new(PrismaClient::_builder().build().await.unwrap());
        let root_keypair = Arc::new(KeyPair::new());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client.clone()))
                .app_data(web::Data::new(root_keypair.clone()))
                .service(register),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/register")
            .insert_header(ContentType::json())
            .set_json(request_data.clone())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body();
        let bytes = body.try_into_bytes();
        assert!(bytes.is_ok());
        let json_string = String::from_utf8(bytes.unwrap().to_vec()).unwrap();
        let json = serde_json::from_str::<RegisterResponse>(&json_string);
        assert!(json.is_ok());
        let new_user = json.unwrap();

        // Check that details in the response match details in the request
        let password_verification = verify(request_data.password.clone(), &new_user.user.password);
        assert!(password_verification.is_ok());
        assert_eq!(password_verification.unwrap(), true);

        // Check that the user exists on the db
        match client
            .user()
            .find_unique(user::id::equals(new_user.user.id.clone()))
            .exec()
            .await
            .unwrap()
        {
            Some(user_data) => {
                assert_eq!(user_data.username, new_user.user.username.clone());
                assert_eq!(user_data.email, new_user.user.email.clone());
                assert_eq!(user_data.password, new_user.user.password.clone());
                assert!(user_data.contacts.is_none());
            }
            None => assert!(false),
        }

        // Check that the token is valid
        let token = String::from(new_user.token.as_str());
        let token = Biscuit::from_base64(&token, root_keypair.public());
        if token.is_err() {
            assert!(false);
        }
        let token = token.unwrap();
        let auth_res = authorize(&token);
        if auth_res.is_err() {
            assert!(false);
        }

        // Now delete the user, thereby resetting the db
        match client
            .user()
            .delete(user::id::equals(new_user.user.id))
            .exec()
            .await
        {
            Ok(user_data) => {
                match client
                    .user()
                    .find_unique(user::id::equals(user_data.id))
                    .exec()
                    .await
                {
                    Ok(_) => assert!(true),
                    Err(_) => assert!(false),
                }
            }
            Err(_) => assert!(false),
        }
    }

    #[actix_web::test]
    async fn test_refresh_user_exists() {
        // Set up a valid user and add it to the database
        let id: String = Uuid::new_v4().to_string();
        let username: String = Uuid::new_v4().to_string();
        let email: String = Uuid::new_v4().to_string();
        let password: String = Uuid::new_v4().to_string();
        let user: user::Data = user::Data {
            id: id,
            username: username,
            email: email,
            password: password,
            contacts: None,
        };

        let client = Arc::new(PrismaClient::_builder().build().await.unwrap());
        let db_user = client
            .user()
            .create(
                user.username.to_string(),
                user.email.to_string(),
                user.password.to_string(),
                vec![],
            )
            .exec()
            .await
            .unwrap();

        // Create the app and call the request, deserialize the expected successful response
        let root_keypair = Arc::new(KeyPair::new());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client.clone()))
                .app_data(web::Data::new(root_keypair.clone()))
                .service(refresh),
        )
        .await;

        // Create a biscuit to emulate a token that would be given on user registration or login
        let biscuit = create_biscuit(root_keypair.clone(), db_user.id.clone());
        if biscuit.is_err() {
            assert!(false)
        }
        let biscuit = biscuit.unwrap().to_base64().unwrap();

        // Create the refresh request adding in the authorization header with a valid biscuit
        // The refresh endpoint relies entirely on the biscuit that encodes user information
        // in the first authority block. This user info is used to check if a user with the
        // info exists on the db. Next, the biscuit itself is authorized. If both of these
        // checks pass, then a new biscuit is created and passed back to the caller.
        let req = test::TestRequest::get()
            .uri("/refresh")
            .insert_header(("Authorization".to_string(), biscuit.clone()))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body();
        let bytes = body.try_into_bytes();
        assert!(bytes.is_ok());
        let json_string = String::from_utf8(bytes.unwrap().to_vec()).unwrap();
        let json = serde_json::from_str::<RefreshResponse>(&json_string);
        assert!(json.is_ok());
        let refresh_response = json.unwrap();

        // Check the contents of the response and make sure they match the user on file and that
        // the refresh token is valid.
        assert_eq!(db_user.id, refresh_response.user.id);
        assert_eq!(db_user.username, refresh_response.user.username);
        assert_eq!(db_user.email, refresh_response.user.email);
        assert_eq!(db_user.password, refresh_response.user.password);
        assert!(refresh_response.user.contacts.is_none());
        let token = String::from(refresh_response.token.as_str());
        let token = Biscuit::from_base64(&token, root_keypair.public());
        if token.is_err() {
            assert!(false);
        }
        let token = token.unwrap();
        let auth_res = authorize(&token);
        if auth_res.is_err() {
            assert!(false);
        }

        // Now delete the user, thereby resetting the db
        match client
            .user()
            .delete(user::id::equals(refresh_response.user.id))
            .exec()
            .await
        {
            Ok(user_data) => {
                match client
                    .user()
                    .find_unique(user::id::equals(user_data.id))
                    .exec()
                    .await
                {
                    Ok(_) => assert!(true),
                    Err(_) => assert!(false),
                }
            }
            Err(_) => assert!(false),
        }
    }
}

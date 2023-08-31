use actix_web::{
    error,
    Result,
    get,
    post,
    put,
    delete,
    web,
    App,
    HttpResponse,
    HttpServer,
    Responder,
    body::BoxBody,
    http::{ header::ContentType, StatusCode },
    HttpRequest,
};
use serde::{ Serialize, Deserialize };
use derive_more::{ Display, Error };

#[derive(Debug, Display, Error)]
enum ContactsError {
    #[display(fmt = "internal error")]
    InternalError,

    #[display(fmt = "bad request")]
    BadClientData,

    #[display(fmt = "timeout")]
    Timeout,
}

impl error::ResponseError for ContactsError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            ContactsError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ContactsError::BadClientData => StatusCode::BAD_REQUEST,
            ContactsError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Contact {
    id: String,
    first_name: String,
    last_name: String,
    email: String,
    tel: String,
}

#[derive(Serialize)]
struct Contacts {
    contacts: Vec<Contact>,
}

impl Responder for Contact {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();
        HttpResponse::Ok().content_type(ContentType::json()).body(body)
    }
}

impl Responder for Contacts {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();
        HttpResponse::Ok().content_type(ContentType::json()).body(body)
    }
}

#[get("/contacts")]
async fn get_contacts() -> Result<Contacts, ContactsError> {
    // Talk to db and get current contacts
    Ok(Contacts {
        contacts: Vec::new(),
    })
}

#[post("/contacts/{contact_id}")]
async fn persist_contact(path: web::Path<String>, contact: web::Json<Contact>) -> Result<Contact, ContactsError> {
    Ok(
        Contact {
            id: contact.id.clone(),
            first_name: contact.first_name.clone(),
            last_name: contact.last_name.clone(),
            email: contact.email.clone(),
            tel: contact.tel.clone()
        }
    )
}

#[put("/contacts/{contact_id}")]
async fn update_contact(path: web::Path<String>, contact: web::Json<Contact>) -> Result<Contact, ContactsError> {
    Ok(
        Contact {
            id: contact.id.clone(),
            first_name: contact.first_name.clone(),
            last_name: contact.last_name.clone(),
            email: contact.email.clone(),
            tel: contact.tel.clone()
        }
    )
}

#[delete("/contacts/{contact_id}")]
async fn delete_contact(path: web::Path<String>, contact: web::Json<Contact>) -> Result<Contact, ContactsError> {
    Ok(
        Contact {
            id: contact.id.clone(),
            first_name: contact.first_name.clone(),
            last_name: contact.last_name.clone(),
            email: contact.email.clone(),
            tel: contact.tel.clone()
        }
    )
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(||
        App::new()
            .service(get_contacts)
            .service(persist_contact)
            .route("/", web::get().to(HttpResponse::Ok))
    )
        .workers(1)
        .bind(("127.0.0.1", 8080))?
        .run().await
}

# Contacts Backend

This repository houses code for a Rust-powered backend for a simple web application that allows registered users to manage a set of contacts. The backend exposes a CRUD api that sits behind an Biscuit-based authentication layer. The backend also exposes endpoints for login, registration, and biscuit token refresh. The client uses the login or register endpoint to get issued an access biscuit token they may use to make further requests on the backend. The backend is also configured with CORS to whitelist request traffic from the frontend client only. Passwords are stored through a hashing algorithm with salt for added security.

## Authors

- [@judahhigh](https://www.github.com/judahhigh)

## Tech Stack

**API Server:** Actix (https://actix.rs/)

**Database:**

- Prisma (https://prisma.brendonovich.dev/)
- SQLite (https://www.sqlite.org/index.html)

**Auth:** Biscuit auth (https://www.biscuitsec.org/)

**Password hashing with salt:** bcrypt (https://docs.rs/bcrypt/latest/bcrypt/)

## Environment Variables

To run this project, you will need to add the following environment variables to a root level .env file

`HOST` The hostname and port of the server, for example "localhost:8080"

`ALLOWED_ORIGIN`The scheme, hostname, and port of the frontend client, for example "http://localhost:3000"

## Run Locally

To run the backend locally you must first install rust and then clone the repository.

```bash
  git clone git@github.com:judahhigh/contacts-backend.git
```

Go to the project directory

```bash
  cd my-project
```

Build the project

```bash
  cargo build
```

Start the backend Actix-web server.

```bash
  cargo run
```

## Running Tests

To run the test suite issue the following command.

```bash
  cargo test
```

## Roadmap

- Dockerize the backend and deploy on a kubernetes cluster on AWS EKS

- Decouple the database REST backend from the authentication backend as a separate container accessible through API Gateway

- Configure CI/CD infrastructure to automatically build and maintain the backend in a production setting
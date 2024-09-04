use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::{web, App, Error, HttpResponse, HttpServer, HttpRequest, Responder};
use futures_util::stream::TryStreamExt;
use futures_util::TryStreamExt as _;
use rusoto_core::Region;
use rusoto_s3::{S3Client, S3, PutObjectRequest};
use serde::{Deserialize, Serialize};
use std::env;
use dotenv::dotenv;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use uuid::Uuid;
use bcrypt::{hash, verify};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

/// Function to create a JWT with a 1-minute expiration time
fn create_jwt(username: &str) -> String {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    // Get the current time and add 60 seconds (1 minute)
    let start = SystemTime::now();
    let duration_since_epoch = start.duration_since(UNIX_EPOCH).unwrap();
    let current_time = duration_since_epoch.as_secs();
    let expiration_time = current_time + 60;  // Token expires in 60 seconds

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration_time as usize,
    };

    // Generate the JWT token
    encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_ref())).unwrap()
}

/// Handler for login route, generates a JWT with 1-minute expiration
async fn login(auth_data: web::Json<AuthData>) -> impl Responder {
    let username = env::var("LOGIN").expect("USERNAME must be set");
    let password = env::var("PASSWORD").expect("PASSWORD must be set");
    let hashed_password = hash(&password, 4).unwrap();
    
    if auth_data.username == username && verify(&auth_data.password, &hashed_password).unwrap() {
        let token = create_jwt(&username);  // Token expires in 60 seconds
        HttpResponse::Ok().json(token)
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

/// Handler for the file upload route, validates JWT and processes the file upload
async fn save_file(req: HttpRequest, mut payload: Multipart) -> Result<HttpResponse, Error> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Get the token from the Authorization header
    let auth_header = req.headers().get("Authorization");

    if let Some(auth_header) = auth_header {
        let token_str = auth_header.to_str().unwrap().replace("Bearer ", "");
        
        // Decode and validate the token
        match decode::<Claims>(&token_str, &DecodingKey::from_secret(jwt_secret.as_ref()), &Validation::default()) {
            Ok(decoded) => {
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                // Check if the token has expired
                if decoded.claims.exp < current_time as usize {
                    return Ok(HttpResponse::Unauthorized().body("Token expired"));
                }

                // Process the file upload since the token is valid
                let mut data = Vec::new();
                while let Some(item) = payload.try_next().await? {
                    let mut field = item;
                    while let Some(chunk) = field.try_next().await? {
                        data.extend_from_slice(&chunk);
                    }
                }

                let bucket = env::var("BUCKET_NAME").expect("BUCKET_NAME must be set");
                let s3 = S3Client::new(Region::default());

                let put_req = PutObjectRequest {
                    bucket,
                    key: Uuid::new_v4().to_string(),
                    body: Some(data.into()),
                    ..Default::default()
                };

                s3.put_object(put_req).await.expect("Failed to upload");
                Ok(HttpResponse::Ok().body("File uploaded successfully"))
            }
            Err(_) => Ok(HttpResponse::Unauthorized().body("Invalid token")),
        }
    } else {
        Ok(HttpResponse::Unauthorized().body("No token provided"))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    HttpServer::new(|| {
        App::new()
            .wrap(Cors::permissive())
            .route("/login", web::post().to(login))
            .route("/upload", web::post().to(save_file))
            .service(actix_files::Files::new("/", "./static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

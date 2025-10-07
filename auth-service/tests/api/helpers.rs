use auth_service::Application;
use uuid::Uuid;
pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread. 
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new();
        
        TestApp { address, http_client }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }
    
    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self, body: &serde_json::Value) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to log in.")
    }

    pub async fn logout(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to log out.")
    }

    pub async fn verify_2fa(&self, body: &serde_json::Value) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to verify 2FA.")
    }
    pub async fn verify_token(&self, token: &str) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to verify token.")
    }

}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
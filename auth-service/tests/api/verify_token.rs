use crate::helpers::TestApp;

#[tokio::test]
async fn verify_token_returns_200() {
    let app = TestApp::new().await;
    let token = "dummy_token";
    // let body = serde_json::json!({
    //     "token": "string"
    // });
    let response = app.verify_token(token).await;
    assert_eq!(response.status().as_u16(), 200);
}
use crate::helpers::TestApp;

#[tokio::test]
async fn logout_returns_200() {
    let app = TestApp::new().await;
    let token = "dummy_token";
    let response = app.logout(token).await;
    assert_eq!(response.status().as_u16(), 200);
}
use crate::domain::{Email, EmailClient};
use color_eyre::eyre::Result;
use secrecy::ExposeSecret;

pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()> {
        // Our mock email client will log the recipient, subject, and content using tracing
        tracing::debug!(
            recipient = %recipient.as_ref().expose_secret(),
            subject = %subject,
            content = %content,
            "Sending email"
        );

        Ok(())
    }
}
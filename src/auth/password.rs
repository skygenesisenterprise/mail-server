use crate::error::{MailServerError, Result};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PasswordManager {
    argon2: Argon2<'static>,
    db_pool: PgPool,
}

impl PasswordManager {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            argon2: Argon2::default(),
            db_pool,
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                MailServerError::Authentication(format!("Failed to hash password: {}", e))
            })?
            .to_string();
        Ok(password_hash)
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| {
            MailServerError::Authentication(format!("Invalid password hash: {}", e))
        })?;

        Ok(self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn validate_password_strength(&self, password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(MailServerError::InvalidInput(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        if !has_upper || !has_lower || !has_digit || !has_special {
            return Err(MailServerError::InvalidInput(
                "Password must contain uppercase, lowercase, digit, and special character"
                    .to_string(),
            ));
        }

        Ok(())
    }

    pub async fn change_password(
        &self,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Get current password hash
        let row = sqlx::query!("SELECT password_hash FROM users WHERE id = $1", user_id)
            .fetch_one(&self.db_pool)
            .await?;

        // Verify old password
        if !self.verify_password(old_password, &row.password_hash)? {
            return Err(MailServerError::Authentication(
                "Current password is incorrect".to_string(),
            ));
        }

        // Validate new password strength
        self.validate_password_strength(new_password)?;

        // Hash new password
        let new_password_hash = self.hash_password(new_password)?;

        // Update password
        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            new_password_hash,
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    pub async fn reset_password(&self, user_id: Uuid, new_password: &str) -> Result<()> {
        // Validate new password strength
        self.validate_password_strength(new_password)?;

        // Hash new password
        let new_password_hash = self.hash_password(new_password)?;

        // Update password and clear failed attempts
        sqlx::query!(
            "UPDATE users SET password_hash = $1, failed_login_attempts = 0, locked_until = NULL WHERE id = $2",
            new_password_hash,
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }
}

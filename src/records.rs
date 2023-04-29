use sqlx::FromRow;

/// A row in the `exits` table.
#[derive(Debug, FromRow)]
pub struct ExitRecord {
    pub hostname: String,
    pub signing_key: [u8; 32],
    pub country: String,
    pub city: String,
    pub sosistab_key: [u8; 32],
    pub plus: bool,
}

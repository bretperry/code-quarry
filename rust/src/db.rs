use anyhow::{Context, Result};
use postgres::{Client, NoTls};

pub fn connect() -> Result<Client> {
    let dsn = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5433/code_scry".into());
    Client::connect(&dsn, NoTls).context("connecting to Postgres (is the container up? docker compose up -d)")
}

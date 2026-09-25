//! Registre des opérateurs, côté `ca-server` (migrations 0002 et 0003,
//! docs/WEBUI.md §2). Seul écrivain : `ra-console` n'y a qu'un accès en
//! lecture (`oe-castore/sql/ra_console_grants.sql`).

use oe_webauthn::{AttestedPasskey, Uuid};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Auditeur,
    RaOperateur,
    CaOperateur,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Auditeur => "auditeur",
            Role::RaOperateur => "ra_operateur",
            Role::CaOperateur => "ca_operateur",
            Role::Admin => "admin",
        }
    }

    fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "auditeur" => Role::Auditeur,
            "ra_operateur" => Role::RaOperateur,
            "ca_operateur" => Role::CaOperateur,
            "admin" => Role::Admin,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Operator {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub disabled: bool,
}

/// Une clé du registre, avec l'état nécessaire pour la vérifier.
#[derive(Clone)]
pub struct Key {
    pub credential_id: String,
    pub operator_id: Uuid,
    pub sign_count: u32,
    pub revoked: bool,
    pub passkey: AttestedPasskey,
}

/// Une clé à inscrire dans le registre. Le drapeau de confirmation
/// (`confirmed_by`) est celui de la contrainte `credential_confirmed_before_active`.
pub struct NewCredential<'a> {
    pub operator_id: Uuid,
    pub passkey: &'a AttestedPasskey,
    pub aaguid: Uuid,
    pub attestation_format: &'a str,
    pub attestation_object: &'a [u8],
    pub label: &'a str,
    pub initiated_by: &'a str,
    pub confirmed_by: Option<&'a str>,
}

/// Identifiant de credential en base64url sans remplissage, la forme que
/// WebAuthn donne à `credential_id`.
pub fn credential_id(raw: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(raw.len() * 4 / 3 + 2);
    for chunk in raw.chunks(3) {
        let n = match chunk.len() {
            3 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
            2 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8),
            _ => u32::from(chunk[0]) << 16,
        };
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

#[derive(Clone)]
pub struct Registry {
    pool: PgPool,
}

impl Registry {
    pub fn new(pool: PgPool) -> Registry {
        Registry { pool }
    }

    /// Ouvre un pool sur `dsn`. Les migrations sont appliquées par
    /// `oe_castore::Postgres::open`, à appeler avant.
    pub async fn connect(dsn: &str) -> Result<Registry, sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(dsn)
            .await?;
        Ok(Registry { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn add_operator(
        &self,
        name: &str,
        role: Role,
        created_by: &str,
        now: OffsetDateTime,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO operators (id, name, role, created_at, created_by)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(name)
        .bind(role.as_str())
        .bind(now)
        .bind(created_by)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Inscrit une clé. Les contraintes SQL (attestation obligatoire, clé non
    /// copiable, confirmation) restent la dernière barrière : ce code ne les
    /// recopie pas.
    pub async fn add_credential(
        &self,
        c: NewCredential<'_>,
        now: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        insert_credential(&mut conn, c, now).await
    }

    pub async fn operator(&self, id: Uuid) -> Result<Option<Operator>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, role, disabled_at FROM operators WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| {
            Some(Operator {
                id: r.get("id"),
                name: r.get("name"),
                role: Role::parse(r.get::<&str, _>("role"))?,
                disabled: r.get::<Option<OffsetDateTime>, _>("disabled_at").is_some(),
            })
        }))
    }

    /// Un opérateur par son nom (connexion, §16 « connexion par nom »). `None`
    /// ne distingue pas un nom absent d'une erreur de frappe : à l'appelant de
    /// répondre de la même forme dans les deux cas.
    pub async fn operator_by_name(&self, name: &str) -> Result<Option<Operator>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, role, disabled_at FROM operators WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| {
            Some(Operator {
                id: r.get("id"),
                name: r.get("name"),
                role: Role::parse(r.get::<&str, _>("role"))?,
                disabled: r.get::<Option<OffsetDateTime>, _>("disabled_at").is_some(),
            })
        }))
    }

    fn key_from_row(r: &sqlx::postgres::PgRow) -> Result<Key, sqlx::Error> {
        let passkey: serde_json::Value = r.get("passkey");
        let passkey = serde_json::from_value(passkey).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let count: i64 = r.get("sign_count");
        Ok(Key {
            credential_id: r.get("credential_id"),
            operator_id: r.get("operator_id"),
            sign_count: u32::try_from(count).unwrap_or(u32::MAX),
            revoked: r.get::<Option<OffsetDateTime>, _>("revoked_at").is_some(),
            passkey,
        })
    }

    /// Les clés actives d'un opérateur, c'est-à-dire non révoquées.
    pub async fn active_keys(&self, operator_id: Uuid) -> Result<Vec<Key>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT credential_id, operator_id, sign_count, revoked_at, passkey
             FROM webauthn_credentials
             WHERE operator_id = $1 AND revoked_at IS NULL
             ORDER BY credential_id",
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::key_from_row).collect()
    }

    /// Une clé par son identifiant, quel que soit son état.
    pub async fn key(&self, credential_id: &str) -> Result<Option<Key>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT credential_id, operator_id, sign_count, revoked_at, passkey
             FROM webauthn_credentials WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::key_from_row).transpose()
    }

    /// Révoque une clé (perte, départ). Utilisé ici par les tests ; l'action
    /// signée qui le fait en production vient dans une tranche suivante.
    pub async fn revoke_key(
        &self,
        credential_id: &str,
        by: &str,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE webauthn_credentials
             SET revoked_at = $2, revoked_by = $3, revoked_reason = $4
             WHERE credential_id = $1 AND revoked_at IS NULL",
        )
        .bind(credential_id)
        .bind(now)
        .bind(by)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_role(&self, id: Uuid, role: Role) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE operators SET role = $2 WHERE id = $1")
            .bind(id)
            .bind(role.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Même inscription, dans la transaction de l'appelant.
pub(crate) async fn insert_credential(
    conn: &mut sqlx::PgConnection,
    c: NewCredential<'_>,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let passkey = serde_json::to_value(c.passkey).map_err(|e| sqlx::Error::Encode(e.into()))?;
    let id = credential_id(c.passkey.cred_id().as_ref());
    sqlx::query(
        "INSERT INTO webauthn_credentials
           (credential_id, operator_id, public_key, aaguid, attestation_format,
            attestation_object, backup_eligible, label, initiated_by, initiated_at,
            confirmed_by, confirmed_at, passkey)
         VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(c.operator_id)
    // Copie lisible sans la bibliothèque : la clé complète est dans `passkey`.
    .bind(passkey.to_string().into_bytes())
    .bind(c.aaguid)
    .bind(c.attestation_format)
    .bind(c.attestation_object)
    .bind(c.label)
    .bind(c.initiated_by)
    .bind(now)
    .bind(c.confirmed_by)
    .bind(c.confirmed_by.map(|_| now))
    .bind(passkey)
    .execute(conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::credential_id;

    #[test]
    fn credential_id_is_base64url_without_padding() {
        // Vecteurs de RFC 4648 §10, en variante URL sans remplissage.
        assert_eq!(credential_id(b""), "");
        assert_eq!(credential_id(b"f"), "Zg");
        assert_eq!(credential_id(b"fo"), "Zm8");
        assert_eq!(credential_id(b"foo"), "Zm9v");
        assert_eq!(credential_id(b"foob"), "Zm9vYg");
        assert_eq!(credential_id(b"fooba"), "Zm9vYmE");
        assert_eq!(credential_id(b"foobar"), "Zm9vYmFy");
        // Les deux caractères propres à la variante URL.
        assert_eq!(credential_id(&[0xfb, 0xff, 0xfe]), "-__-");
    }
}

//! Branche `oe_ca_core::Issuer` sur l'action signée de révocation de
//! certificat (`oe_actions::Revoker`).

use std::sync::Arc;

use oe_ca_core::Issuer;

pub struct IssuerRevoker(pub Arc<Issuer>);

#[async_trait::async_trait]
impl oe_actions::Revoker for IssuerRevoker {
    async fn revoke(
        &self,
        serial: &[u8],
        reason: i32,
        operator: &str,
        comment: &str,
    ) -> Result<(), String> {
        self.0
            .revoke(serial, reason, operator, comment)
            .await
            .map_err(|e| e.to_string())
    }

    async fn publish_crl(&self) -> Result<i64, String> {
        self.0
            .publish_crl()
            .await
            .map(|crl| crl.number)
            .map_err(|e| e.to_string())
    }
}

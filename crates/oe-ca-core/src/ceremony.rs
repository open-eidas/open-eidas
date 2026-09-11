//! Portage de `internal/ca/ceremony.go` : crée la hiérarchie racine +
//! émettrice si elle n'existe pas encore, se contente de la relire sinon.
//! L'idempotence est délibérée (voir le fichier Go de référence).

use der::{Decode, Encode};
use x509_cert::builder::CertificateBuilder;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::{Certificate, SubjectPublicKeyInfo};

use oe_castore::{Authority, Store};
use oe_hsm::SigningToken;

use crate::{build_subject, extensions, matches_signer, to_x509_time, CaError, RawProfile};

pub const AUTHORITY_ROOT: &str = "root";
pub const AUTHORITY_ISSUING: &str = "issuing";

pub struct CeremonyOptions {
    pub root_signer: std::sync::Arc<dyn SigningToken + Send + Sync>,
    pub issuing_signer: std::sync::Arc<dyn SigningToken + Send + Sync>,
    pub root_cn: String,
    pub issuing_cn: String,
    pub organization: String,
    pub country: String,
    pub root_validity: time::Duration,
    pub issuing_validity: time::Duration,
    pub root_token_label: String,
    pub root_key_label: String,
    pub issuing_token_label: String,
    pub issuing_key_label: String,
    pub store: std::sync::Arc<dyn Store>,
    pub operator: String,
}

pub struct Hierarchy {
    pub root: Certificate,
    pub issuing: Certificate,
    /// `false` lorsque la hiérarchie existait déjà et a simplement été
    /// relue : la cérémonie est idempotente.
    pub created: bool,
}

pub async fn run_ceremony(o: CeremonyOptions) -> Result<Hierarchy, CaError> {
    if o.operator.is_empty() {
        return Err(CaError::Other("la cérémonie exige l'identité de l'opérateur qui la conduit".to_string()));
    }

    if let Some(existing) = load_hierarchy(o.store.as_ref()).await? {
        let root_spki = existing.root.tbs_certificate().subject_public_key_info().to_der()?;
        matches_signer(&root_spki, o.root_signer.as_ref()).map_err(|e| CaError::Other(format!("racine déjà enregistrée mais clé du token différente: {e}")))?;
        let issuing_spki = existing.issuing.tbs_certificate().subject_public_key_info().to_der()?;
        matches_signer(&issuing_spki, o.issuing_signer.as_ref()).map_err(|e| CaError::Other(format!("émettrice déjà enregistrée mais clé du token différente: {e}")))?;
        return Ok(Hierarchy { root: existing.root, issuing: existing.issuing, created: false });
    }

    let now = time::OffsetDateTime::now_utc();
    let root = sign_root(&o, now).await?;
    let issuing = sign_issuing(&o, now, &root).await?;

    for a in [
        Authority { name: AUTHORITY_ROOT.to_string(), subject_dn: root.tbs_certificate().subject().to_string(), der: root.to_der()?, token_label: o.root_token_label.clone(), key_label: o.root_key_label.clone(), created_at: now },
        Authority { name: AUTHORITY_ISSUING.to_string(), subject_dn: issuing.tbs_certificate().subject().to_string(), der: issuing.to_der()?, token_label: o.issuing_token_label.clone(), key_label: o.issuing_key_label.clone(), created_at: now },
    ] {
        o.store.save_authority(a).await?;
    }

    Ok(Hierarchy { root, issuing, created: true })
}

async fn sign_root(o: &CeremonyOptions, now: time::OffsetDateTime) -> Result<Certificate, CaError> {
    let root_cn = if o.root_cn.is_empty() { "Open eIDAS Root CA" } else { &o.root_cn };
    let organization = if o.organization.is_empty() { "Open eIDAS" } else { &o.organization };
    let country = if o.country.is_empty() { "FR" } else { &o.country };
    let validity = if o.root_validity.is_zero() { time::Duration::days(20 * 365) } else { o.root_validity };

    let subject = build_subject(root_cn, "", organization, country)?;
    let spki_der = o.root_signer.public_key_der()?;
    let ski = crate::signing::subject_key_id(&spki_der)?;

    let exts = vec![
        // La racine ne signe qu'une CA émettrice, qui ne signe que des
        // entités finales : pathLenConstraint = 1 interdit toute
        // sous-autorité supplémentaire.
        extensions::basic_constraints(true, Some(1))?,
        extensions::key_usage(x509_cert::ext::pkix::KeyUsages::KeyCertSign | x509_cert::ext::pkix::KeyUsages::CRLSign)?,
        extensions::subject_key_identifier(&ski)?,
    ];

    let not_before = to_x509_time(now - time::Duration::minutes(5))?;
    let not_after = to_x509_time(now + validity)?;
    let spki = SubjectPublicKeyInfo::from_der(&spki_der)?;
    let profile = RawProfile { subject: subject.clone(), issuer: subject, extensions: exts };
    let builder = CertificateBuilder::new(profile, SerialNumber::new(&random_serial())?, Validity::new(not_before, not_after), spki).map_err(|e| CaError::Other(e.to_string()))?;
    crate::signing::sign_with_token(builder, o.root_signer.as_ref(), &spki_der)
}

async fn sign_issuing(o: &CeremonyOptions, now: time::OffsetDateTime, root: &Certificate) -> Result<Certificate, CaError> {
    let issuing_cn = if o.issuing_cn.is_empty() { "Open eIDAS Issuing CA" } else { &o.issuing_cn };
    let organization = if o.organization.is_empty() { "Open eIDAS" } else { &o.organization };
    let country = if o.country.is_empty() { "FR" } else { &o.country };
    let validity = if o.issuing_validity.is_zero() { time::Duration::days(10 * 365) } else { o.issuing_validity };

    let subject = build_subject(issuing_cn, "", organization, country)?;
    let spki_der = o.issuing_signer.public_key_der()?;
    let ski = crate::signing::subject_key_id(&spki_der)?;
    let root_spki_der = root.tbs_certificate().subject_public_key_info().to_der()?;
    let root_ski = crate::signing::subject_key_id(&root_spki_der)?;

    let not_before = to_x509_time(now - time::Duration::minutes(5))?;
    // Une émettrice qui survivrait à sa racine émettrait des certificats
    // invérifiables sur sa dernière période.
    let root_not_after = root.tbs_certificate().validity().not_after.to_date_time();
    let root_not_after = time::OffsetDateTime::from_unix_timestamp(root_not_after.unix_duration().as_secs() as i64).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let not_after_dt = std::cmp::min(now + validity, root_not_after);
    let not_after = to_x509_time(not_after_dt)?;

    let exts = vec![
        extensions::basic_constraints(true, Some(0))?,
        extensions::key_usage(x509_cert::ext::pkix::KeyUsages::KeyCertSign | x509_cert::ext::pkix::KeyUsages::CRLSign)?,
        extensions::subject_key_identifier(&ski)?,
        extensions::authority_key_identifier(&root_ski)?,
    ];

    let spki = SubjectPublicKeyInfo::from_der(&spki_der)?;
    let profile = RawProfile { subject, issuer: root.tbs_certificate().subject().clone(), extensions: exts };
    let builder = CertificateBuilder::new(profile, SerialNumber::new(&random_serial())?, Validity::new(not_before, not_after), spki).map_err(|e| CaError::Other(e.to_string()))?;
    // Signée par la clé de la RACINE, pas par celle de l'émettrice
    // elle-même : c'est ce qui fait d'elle une autorité subordonnée.
    crate::signing::sign_with_token(builder, o.root_signer.as_ref(), &root_spki_der)
}

fn random_serial() -> Vec<u8> {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes[0] |= 0x80;
    bytes.to_vec()
}

pub async fn load_hierarchy(store: &dyn Store) -> Result<Option<Hierarchy>, CaError> {
    let root = match store.authority(AUTHORITY_ROOT).await {
        Ok(a) => a,
        Err(oe_castore::StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let issuing = match store.authority(AUTHORITY_ISSUING).await {
        Ok(a) => a,
        Err(oe_castore::StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(Hierarchy { root: Certificate::from_der(&root.der)?, issuing: Certificate::from_der(&issuing.der)?, created: false }))
}

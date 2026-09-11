//! Portage de `internal/ca/profile.go` : ce que contient un certificat émis
//! par cette autorité, sous forme de structure Rust compilée et testée — et
//! non de configuration interprétée au démarrage (voir INDEPENDANCE.md).

use der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

pub const PROFILE_TSA_SIGNER: &str = "tsa_signer";
pub const PROFILE_OCSP_RESPONDER: &str = "ocsp_responder";

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(s).expect("OID constant invalide")
}

/// Décrit ce qu'un certificat émis par cette autorité contient.
pub struct Profile {
    pub name: &'static str,
    pub label: &'static str,

    /// Parties fixes du sujet. Seul le CN provient de la CSR : le reste est
    /// imposé par l'autorité.
    pub organizational_unit: &'static str,
    pub organization: &'static str,
    pub country: &'static str,

    pub validity: time::Duration,

    pub key_usages: der::flagset::FlagSet<KeyUsages>,
    pub eku: &'static [&'static str],
    /// ETSI EN 319 421 §7.7.2 exige `extendedKeyUsage` critique pour un
    /// certificat de TSU : sans criticité, un vérificateur peut ignorer la
    /// restriction d'usage.
    pub eku_critical: bool,

    /// Ajoute `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1).
    pub ocsp_no_check: bool,

    pub include_crl_distribution_point: bool,
    pub include_ca_issuers: bool,
    pub include_ocsp_responder: bool,
}

pub const OID_EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const OID_EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
/// `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1).
pub const OID_OCSP_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";

pub fn eku_oids(p: &Profile) -> Vec<ObjectIdentifier> {
    p.eku.iter().map(|s| oid(s)).collect()
}

/// Reproduit le profil ETSI EN 319 422 / EN 319 421 §7.7.2 de l'unité
/// d'horodatage.
pub fn tsa_signer() -> Profile {
    Profile {
        name: PROFILE_TSA_SIGNER,
        label: "Open eIDAS Time-Stamping Unit",
        organizational_unit: "Time Stamping Authority",
        organization: "Open eIDAS",
        country: "FR",
        validity: time::Duration::days(365),
        // nonRepudiation (contentCommitment) accompagne digitalSignature :
        // un jeton d'horodatage engage l'autorité sur la date.
        key_usages: KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
        eku: &[OID_EKU_TIME_STAMPING],
        eku_critical: true,
        ocsp_no_check: false,
        include_crl_distribution_point: true,
        include_ca_issuers: true,
        include_ocsp_responder: true,
    }
}

/// Reproduit le profil du répondeur OCSP. Ni CDP ni AIA : `ocsp-nocheck`
/// dispense de vérifier la révocation de ce certificat, la durée de vie
/// courte est la contrepartie de cette dispense.
pub fn ocsp_responder() -> Profile {
    Profile {
        name: PROFILE_OCSP_RESPONDER,
        label: "Open eIDAS OCSP Responder",
        organizational_unit: "OCSP Responder",
        organization: "Open eIDAS",
        country: "FR",
        validity: time::Duration::days(90),
        key_usages: KeyUsages::DigitalSignature.into(),
        eku: &[OID_EKU_OCSP_SIGNING],
        eku_critical: true,
        ocsp_no_check: true,
        include_crl_distribution_point: false,
        include_ca_issuers: false,
        include_ocsp_responder: false,
    }
}

/// Nom inconnu : erreur explicite, aucun profil par défaut n'est appliqué
/// en silence — l'héritage implicite qui piégeait la configuration OpenXPKI.
pub fn profile_by_name(name: &str) -> Result<Profile, String> {
    match name {
        PROFILE_TSA_SIGNER => Ok(tsa_signer()),
        PROFILE_OCSP_RESPONDER => Ok(ocsp_responder()),
        other => Err(format!("ca: profil de certificat inconnu: {other:?}")),
    }
}

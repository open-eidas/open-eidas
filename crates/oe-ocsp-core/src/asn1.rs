//! Structures ASN.1 RFC 6960 (OCSP). Aucune crate Rust compatible avec notre
//! stack `der`/`x509-cert` (0.8/0.3) ne couvre ce protocole — définies ici à
//! l'identique de la démarche retenue pour RFC 3161
//! (`oe_rfc3161_asn1`) plutôt que d'introduire une seconde pile ASN.1
//! incompatible (la crate `ocsp` disponible s'appuie sur `asn1_der`, sans
//! rapport avec `der`).

use der::asn1::{BitString, Int, Null, ObjectIdentifier, OctetString};
use der::{Any, Choice, Enumerated, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::crl::CrlReason;
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::Certificate;

/// `CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, issuerNameHash
/// OCTET STRING, issuerKeyHash OCTET STRING, serialNumber
/// CertificateSerialNumber }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: Int,
}

/// `Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0]
/// EXPLICIT Extensions OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspSingleRequest {
    pub req_cert: CertId,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub single_request_extensions: Option<Extensions>,
}

/// `TBSRequest ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1,
/// requestorName [1] EXPLICIT GeneralName OPTIONAL, requestList SEQUENCE OF
/// Request, requestExtensions [2] EXPLICIT Extensions OPTIONAL }`
///
/// `requestorName` (GeneralName, CHOICE) est conservé opaque, à l'identique
/// de `TstInfo.tsa` côté RFC 3161 — le répondeur Go ne l'exploite pas non plus.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsRequest {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub version: Option<u8>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub requestor_name: Option<Any>,
    pub request_list: Vec<OcspSingleRequest>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub request_extensions: Option<Extensions>,
}

/// `OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0]
/// EXPLICIT Signature OPTIONAL }`
///
/// La signature de requête est optionnelle en RFC 6960 et n'est pas
/// vérifiée par le répondeur Go de référence ; conservée opaque ici aussi.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspRequest {
    pub tbs_request: TbsRequest,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub optional_signature: Option<Any>,
}

/// `OCSPResponseStatus ::= ENUMERATED { successful (0), malformedRequest
/// (1), internalError (2), tryLater (3), sigRequired (5), unauthorized (6) }`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumerated)]
#[repr(u8)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

/// `ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response
/// OCTET STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseBytes {
    pub response_type: ObjectIdentifier,
    pub response: OctetString,
}

/// `OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus,
/// responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspResponse {
    pub response_status: OcspResponseStatus,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub response_bytes: Option<ResponseBytes>,
}

/// `ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }`. `Name`
/// est un CHOICE : le tag `[1]` est donc EXPLICIT (X.680 §31.2.7), comme le
/// fait le répondeur Go de référence (`RawResponderID` avec `IsCompound: true`).
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    ByKey(OctetString),
}

impl ValueOrd for ResponderId {
    fn value_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        use der::DerOrd;
        self.der_cmp(other)
    }
}

/// `RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
/// revocationReason [0] EXPLICIT CRLReason OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedInfo {
    pub revocation_time: der::asn1::GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub revocation_reason: Option<CrlReason>,
}

/// `CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT
/// RevokedInfo, unknown [2] IMPLICIT NULL }`
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}

impl ValueOrd for CertStatus {
    fn value_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        use der::DerOrd;
        self.der_cmp(other)
    }
}

/// `SingleResponse ::= SEQUENCE { certID CertID, certStatus CertStatus,
/// thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT GeneralizedTime
/// OPTIONAL, singleExtensions [1] EXPLICIT Extensions OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: der::asn1::GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub next_update: Option<der::asn1::GeneralizedTime>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub single_extensions: Option<Extensions>,
}

/// `ResponseData ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1,
/// responderID ResponderID, producedAt GeneralizedTime, responses SEQUENCE
/// OF SingleResponse, responseExtensions [1] EXPLICIT Extensions OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseData {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub version: Option<u8>,
    pub responder_id: ResponderId,
    pub produced_at: der::asn1::GeneralizedTime,
    pub responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub response_extensions: Option<Extensions>,
}

/// `BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData,
/// signatureAlgorithm AlgorithmIdentifier, signature BIT STRING, certs [0]
/// EXPLICIT SEQUENCE OF Certificate OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub certs: Option<Vec<Certificate>>,
}

/// OID `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1).
pub const OID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

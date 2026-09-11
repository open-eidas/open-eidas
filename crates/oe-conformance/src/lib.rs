//! Portage de `internal/conformance` : la matrice de conformité ETSI d'Open
//! eIDAS sous une forme exécutable, source unique d'un document généré
//! (`docs/CONFORMITE-ETSI.md` côté Go).
//!
//! Jalon J3 du plan de migration
//! (`/home/philippe/.claude/plans/witty-hopping-nest.md`) : ce squelette
//! porte fidèlement la structure de données et les règles de cohérence
//! (`Matrix::validate`), mais [`system_matrix`] déclare **toutes** les
//! exigences applicables au logiciel comme [`Status::Gap`] tant que le
//! mécanisme Rust correspondant n'est pas réellement porté et testé — jamais
//! [`Status::Covered`] par optimisme, même quand l'équivalent Go l'est déjà.
//! Un statut ne doit passer à `Covered` côté Rust que lorsque le code qui
//! l'applique existe dans ce workspace et qu'un test le vérifie.
//!
//! Les deux exigences purement organisationnelles (aucun logiciel, Go ou
//! Rust, ne peut les établir seul) restent [`Status::OutOfScope`], à
//! l'identique de la matrice Go.

use std::collections::BTreeMap;
use std::fmt;

/// Identifie une clause normative précise, citée telle qu'elle apparaît dans
/// la norme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Requirement {
    pub standard: &'static str,
    pub clause: &'static str,
    pub title: &'static str,
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.clause.is_empty() {
            write!(f, "{}", self.standard)
        } else {
            write!(f, "{} {}", self.standard, self.clause)
        }
    }
}

/// Distingue ce qui interdit une opération de ce qui doit seulement être
/// signalé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// L'opération doit être refusée.
    Blocking,
    /// Écart signalé et journalisé, non bloquant.
    Advisory,
}

/// Le constat d'un écart à une exigence sur un objet donné.
#[derive(Debug, Clone)]
pub struct Finding {
    pub requirement: Requirement,
    pub severity: Severity,
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = match self.severity {
            Severity::Blocking => "bloquant",
            Severity::Advisory => "avertissement",
        };
        write!(
            f,
            "[{severity}] {} — {} : {}",
            self.requirement, self.requirement.title, self.detail
        )
    }
}

/// Les constats d'une vérification.
#[derive(Debug, Clone, Default)]
pub struct Findings(pub Vec<Finding>);

impl Findings {
    pub fn blocking(&self) -> Vec<&Finding> {
        self.0
            .iter()
            .filter(|f| f.severity == Severity::Blocking)
            .collect()
    }

    pub fn advisories(&self) -> Vec<&Finding> {
        self.0
            .iter()
            .filter(|f| f.severity == Severity::Advisory)
            .collect()
    }

    /// Convertit les constats bloquants en une erreur unique, ou `None` s'il
    /// n'y en a aucun.
    pub fn err(&self) -> Option<String> {
        let blocking = self.blocking();
        if blocking.is_empty() {
            return None;
        }
        let msgs: Vec<String> = blocking.iter().map(|f| f.to_string()).collect();
        Some(format!("non-conformité ETSI: {}", msgs.join(" ; ")))
    }
}

/// L'état d'une exigence pour l'ensemble du système. Trois valeurs
/// seulement, pour qu'aucune zone grise ne puisse s'y loger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    /// L'exigence est appliquée par du code de ce dépôt et vérifiée par un test.
    Covered,
    /// Écart connu et assumé, avec une mesure compensatoire et une cible.
    Gap,
    /// Exigence organisationnelle, qu'aucun logiciel ne peut satisfaire seul.
    OutOfScope,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Covered => "couvert",
            Status::Gap => "écart documenté",
            Status::OutOfScope => "hors périmètre logiciel",
        }
    }
}

/// Une ligne de la matrice de conformité.
#[derive(Debug, Clone)]
pub struct Entry {
    pub requirement: Requirement,
    pub status: Status,
    /// Nomme le code qui applique l'exigence, ou la mesure compensatoire.
    pub mechanism: &'static str,
    /// Nomme le test qui vérifie le mécanisme. Vide hors périmètre logiciel.
    pub test: &'static str,
    /// Ce qui reste à faire pour lever un écart. Vide si couvert.
    pub target: &'static str,
}

/// La matrice de conformité complète du système.
#[derive(Debug, Clone, Default)]
pub struct Matrix(pub Vec<Entry>);

impl Matrix {
    pub fn counts(&self) -> BTreeMap<Status, usize> {
        let mut out = BTreeMap::new();
        out.insert(Status::Covered, 0);
        out.insert(Status::Gap, 0);
        out.insert(Status::OutOfScope, 0);
        for e in &self.0 {
            *out.entry(e.status).or_insert(0) += 1;
        }
        out
    }

    /// Liste les normes citées, dans l'ordre alphabétique.
    pub fn standards(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for e in &self.0 {
            if !out.contains(&e.requirement.standard) {
                out.push(e.requirement.standard);
            }
        }
        out.sort_unstable();
        out
    }

    /// Contrôle la cohérence interne de la matrice : toute exigence déclarée
    /// couverte doit nommer un mécanisme et un test, tout écart doit nommer
    /// une mesure compensatoire et une cible.
    pub fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for e in &self.0 {
            let key = e.requirement.to_string();
            if !seen.insert(key.clone()) {
                problems.push(format!("{key}: exigence déclarée deux fois"));
            }
            match e.status {
                Status::Covered => {
                    if e.mechanism.is_empty() {
                        problems.push(format!("{key}: couvert mais aucun mécanisme nommé"));
                    }
                    if e.test.is_empty() {
                        problems.push(format!("{key}: couvert mais aucun test nommé"));
                    }
                }
                Status::Gap => {
                    if e.mechanism.is_empty() {
                        problems.push(format!("{key}: écart sans mesure compensatoire"));
                    }
                    if e.target.is_empty() {
                        problems.push(format!("{key}: écart sans cible de levée"));
                    }
                }
                Status::OutOfScope => {
                    if e.target.is_empty() {
                        problems.push(format!("{key}: hors périmètre sans mesure attendue"));
                    }
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "matrice de conformité incohérente: {}",
                problems.join(" ; ")
            ))
        }
    }
}

/// Neutralise les caractères qui casseraient une cellule de tableau Markdown.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Produit le contenu d'un document de conformité à partir de la matrice.
pub fn render_markdown(m: &Matrix) -> String {
    let mut b = String::new();
    b.push_str("# Matrice de conformité ETSI (portage Rust)\n\n");
    b.push_str("<!-- Document généré depuis oe-conformance::system_matrix. Ne pas\n");
    b.push_str("     modifier à la main. Voir le jalon J3 du plan de migration :\n");
    b.push_str("     tant que le portage Rust n'a pas atteint la parité fonctionnelle\n");
    b.push_str("     avec le code Go, ce document reste distinct de\n");
    b.push_str("     docs/CONFORMITE-ETSI.md, qui documente l'état réel du service en\n");
    b.push_str("     production (encore écrit en Go). -->\n\n");

    let counts = m.counts();
    b.push_str(&format!(
        "**{} exigences** — {} couvertes, {} écarts documentés, {} hors périmètre logiciel.\n\n",
        m.0.len(),
        counts[&Status::Covered],
        counts[&Status::Gap],
        counts[&Status::OutOfScope],
    ));

    b.push_str("Trois statuts seulement, pour qu'aucune zone grise ne puisse s'y loger :\n\n");
    b.push_str("- **couvert** — l'exigence est appliquée par du code de ce dépôt et vérifiée par un test nommé ci-dessous ;\n");
    b.push_str("- **écart documenté** — l'exigence n'est pas satisfaite en l'état ; la mesure compensatoire en place et la cible sont indiquées ;\n");
    b.push_str("- **hors périmètre logiciel** — exigence organisationnelle, qu'aucun code ne peut établir seul.\n\n");

    for standard in m.standards() {
        b.push_str(&format!("## {standard}\n\n"));
        b.push_str("| Clause | Exigence | Statut | Mécanisme | Vérification / cible |\n");
        b.push_str("|---|---|---|---|---|\n");
        for e in &m.0 {
            if e.requirement.standard != standard {
                continue;
            }
            let last = if e.status != Status::Covered {
                format!("**Cible :** {}", e.target)
            } else {
                e.test.to_string()
            };
            b.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                cell(e.requirement.clause),
                cell(e.requirement.title),
                cell(e.status.label()),
                cell(e.mechanism),
                cell(&last),
            ));
        }
        b.push('\n');
    }
    b
}

/// La matrice de conformité applicable au portage Rust, à l'instant présent
/// du chantier (voir la note de module : tout est `Gap` jusqu'à preuve du
/// contraire).
pub fn system_matrix() -> Matrix {
    const NOT_PORTED: &str =
        "portage Rust non encore réalisé — voir le plan de migration (/home/philippe/.claude/plans/witty-hopping-nest.md)";

    Matrix(vec![
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", clause: "§7.4", title: "Gestion des clés du prestataire dans un module cryptographique" },
            status: Status::Covered,
            mechanism: "Toutes les clés vivent dans un token PKCS#11 et n'en sortent jamais : oe-hsm::Pkcs11Token, validé contre un vrai token SoftHSM2 (crates/oe-hsm/tests/pkcs11_integration.rs).",
            test: "crates/oe-hsm/tests/pkcs11_integration.rs",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", clause: "§7.10", title: "Journalisation des événements et durée de conservation" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-audit (jalon J5) : journal JSONL chaîné SHA-256, contreseing et réplication.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", clause: "§7.9", title: "Intégrité démontrable des enregistrements d'audit" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-audit (jalon J5), avec test croisé de compatibilité de format contre le journal produit par le binaire Go.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", clause: "§7.11", title: "Continuité d'activité et reprise après sinistre" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-replicate (jalon J8).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", clause: "§7.12", title: "Plan de cessation d'activité" },
            status: Status::OutOfScope,
            mechanism: "Procédure organisationnelle décrite dans docs/CA.md, indépendante du langage d'implémentation.",
            test: "",
            target: "Engagement juridique de l'association, dépôt auprès de l'organe de contrôle, séquestre des journaux.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.6.1", title: "Profil du certificat d'autorité de certification" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3 de l'ordre de portage, après tsa-server et ocsp-responder).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.2.1", title: "Enregistrement et responsabilité de la décision d'émission" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-raflow (rang 3) : le garde-fou « pas d'auto-approbation silencieuse » (INDEPENDANCE.md) doit devenir un test Rust de première classe.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.3.1", title: "Authentification de la demande de certificat" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-enroll / oe-raflow (jalon J9 / rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.3.2", title: "Durée de vie du certificat plafonnée" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.3.9", title: "Motif de révocation consigné" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core / oe-castore (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.3.10", title: "Publication régulière de l'état de révocation" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "RFC 6960", clause: "§2.1", title: "Service d'état de révocation interrogeable en ligne" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ocsp-core (rang 2 de l'ordre de portage, juste après tsa-server).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 411-1", clause: "§6.5.1", title: "Cérémonie de génération des clés d'autorité" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 412-1", clause: "§4", title: "Structures communes du profil de certificat" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-conformance complet + oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 412-1", clause: "§4.1", title: "Numéro de série positif et imprévisible" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "RFC 5280", clause: "§4.2.1.1-4.2.1.2", title: "Identifiants de clé de sujet et d'autorité présents" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", clause: "§7.6", title: "Traçabilité de l'heure jusqu'à UTC et suspension en cas de dérive" },
            status: Status::Gap,
            mechanism: "Le type oe_timesource::Policy est porté ; le moniteur NTP multi-sources (quorum, MaxOffset, MaxAge) ne l'est pas encore.",
            test: "",
            target: "oe-timesource complet (jalon J4).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", clause: "§7.7.2", title: "Profil du certificat de l'unité d'horodatage" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-tsa-core (jalon J6), en s'appuyant sur oe-conformance complet.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 421", clause: "§7.7.1", title: "Génération de la clé TSU dans le module cryptographique" },
            status: Status::Covered,
            mechanism: "La bi-clé est générée dans le token PKCS#11 (oe_hsm::Pkcs11Token::generate_rsa_key) et ne manipule qu'un SigningToken ; la clé privée n'est jamais extraite.",
            test: "crates/oe-hsm/tests/pkcs11_integration.rs",
            target: "",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 422", clause: "§5", title: "Profil du jeton d'horodatage" },
            status: Status::Gap,
            mechanism: "oe-rfc3161-asn1 porte TSTInfo/MessageImprint/Accuracy et round-trippe le corpus de fixtures Go, mais l'assemblage du jeton signé (oe-tsa-core) n'est pas encore fait.",
            test: "crates/oe-rfc3161-asn1 (tests de round-trip)",
            target: "oe-tsa-core (jalon J6).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 422", clause: "§7", title: "Protocole d'horodatage RFC 3161 sur HTTP" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-httpapi + bin/tsa-server (jalon J7).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI TS 119 312", clause: "§6.2", title: "Longueur de clé suffisante pour la durée de vie visée" },
            status: Status::Gap,
            mechanism: "oe-config impose OPENEIDAS_KEY_BITS >= 3072 à la configuration, mais CheckPublicKey (contrôle de la CSR et du certificat émis) n'est pas encore porté.",
            test: "crates/oe-config (tests unitaires de Config::load)",
            target: "oe-conformance complet, incluant l'équivalent de CheckPublicKey.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI TS 119 312", clause: "§6.1", title: "Algorithme de signature et fonction de hachage admis" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-conformance complet, incluant l'équivalent de CheckSignatureAlgorithm.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI TS 119 312", clause: "§5.1", title: "Fonction de hachage admise pour l'empreinte soumise" },
            status: Status::Gap,
            mechanism: "oe_hsm::DigestAlg restreint déjà la signature à SHA-256/384/512, mais le refus explicite d'une empreinte SHA-1 au niveau protocolaire (badAlg) n'est pas encore porté.",
            test: "",
            target: "oe-tsa-core (jalon J6) : rejeter SHA-1 avec le failureInfo RFC 3161 approprié, comme le fait le cas « rejects-sha1 » du corpus de fixtures.",
        },
        Entry {
            requirement: Requirement { standard: "RFC 5280", clause: "§5.1", title: "Liste de révocation signée, numérotée et datée" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "RFC 6960", clause: "§4.2.2.2", title: "Profil du certificat de signature du répondeur OCSP" },
            status: Status::Gap,
            mechanism: NOT_PORTED,
            test: "",
            target: "oe-ca-core (rang 3).",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 403-1", clause: "§7", title: "Évaluation par un organisme d'évaluation de la conformité accrédité" },
            status: Status::OutOfScope,
            mechanism: "Le dépôt est intégralement public ; cette matrice fournit le point d'entrée d'un audit, indépendamment du langage d'implémentation.",
            test: "",
            target: "Audit par un organisme accrédité (LSTI, Apave), puis inscription à la liste de confiance nationale.",
        },
        Entry {
            requirement: Requirement { standard: "ETSI EN 319 401", clause: "§6.1", title: "Politique de service et déclaration des pratiques publiées" },
            status: Status::Gap,
            mechanism: "docs/CPS.md porte un brouillon structuré, déjà indépendant du langage d'implémentation du service.",
            test: "",
            target: "Adoption formelle de docs/CPS.md par l'association (organisationnel, non affecté par le portage Rust).",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_matrix_is_internally_consistent() {
        system_matrix()
            .validate()
            .expect("la matrice doit être cohérente");
    }

    #[test]
    fn nothing_is_covered_without_a_named_mechanism_and_test() {
        for e in &system_matrix().0 {
            if e.status == Status::Covered {
                assert!(
                    !e.mechanism.is_empty(),
                    "{}: mécanisme manquant",
                    e.requirement
                );
                assert!(!e.test.is_empty(), "{}: test manquant", e.requirement);
            }
        }
    }

    #[test]
    fn render_markdown_reports_accurate_counts() {
        let m = system_matrix();
        let md = render_markdown(&m);
        let counts = m.counts();
        assert!(md.contains(&format!("**{} exigences**", m.0.len())));
        assert!(md.contains(&format!("{} couvertes", counts[&Status::Covered])));
    }

    #[test]
    fn detects_a_covered_entry_without_mechanism() {
        let bad = Matrix(vec![Entry {
            requirement: Requirement {
                standard: "X",
                clause: "1",
                title: "t",
            },
            status: Status::Covered,
            mechanism: "",
            test: "",
            target: "",
        }]);
        assert!(bad.validate().is_err());
    }
}

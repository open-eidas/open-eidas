// Package conformance porte, en un seul endroit du dépôt, les exigences
// normatives ETSI applicables à Open eIDAS sous une forme exécutable.
//
// L'intention est qu'aucune règle ETSI ne soit énoncée deux fois : chaque
// exigence technique est définie ici une fois, puis utilisée à trois endroits
// qui ne peuvent pas diverger —
//
//  1. les tests unitaires de ce paquet, un test par règle ;
//  2. les gardes d'exécution : le moteur de CA relit le certificat qu'il vient
//     d'émettre et refuse de le délivrer s'il échoue une règle, la TSA refuse
//     de démarrer sur un certificat non conforme ;
//  3. le rapport `ca-server conformance` / `tsa-server conformance`, qui rend
//     la matrice de docs/CONFORMITE-ETSI.md vérifiable en continu.
//
// Ce paquet ne couvre que ce qu'un logiciel peut établir. Les exigences
// organisationnelles (HSM certifié, opérateur RA humain nominatif, double
// contrôle en cérémonie, audit par un organisme accrédité) sont portées par la
// matrice avec le statut StatusOutOfScope : elles sont énoncées, pas prouvées.
package conformance

import (
	"fmt"
	"sort"
	"strings"
)

// Severity distingue ce qui interdit la délivrance d'un certificat ou le
// démarrage d'un service de ce qui doit seulement être signalé.
type Severity string

const (
	// Blocking : l'opération doit être refusée. Un certificat qui échoue une
	// règle bloquante ne doit jamais sortir du service.
	Blocking Severity = "bloquant"
	// Advisory : écart signalé et journalisé, non bloquant pour un
	// déploiement de démonstration.
	Advisory Severity = "avertissement"
)

// Requirement identifie une clause normative précise. La clause est citée
// telle qu'elle apparaît dans la norme, pour qu'un auditeur puisse la
// retrouver sans interprétation.
type Requirement struct {
	Standard string // ex. "ETSI EN 319 421"
	Clause   string // ex. "§7.7.2"
	Title    string // libellé court de l'exigence
}

func (r Requirement) String() string {
	if r.Clause == "" {
		return r.Standard
	}
	return r.Standard + " " + r.Clause
}

// Finding est le constat d'un écart à une exigence sur un objet donné.
type Finding struct {
	Requirement Requirement
	Severity    Severity
	Detail      string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s — %s : %s", f.Severity, f.Requirement, f.Requirement.Title, f.Detail)
}

// Findings regroupe les constats d'une vérification.
type Findings []Finding

// Blocking retourne les seuls constats qui doivent faire échouer l'opération.
func (f Findings) Blocking() Findings {
	var out Findings
	for _, item := range f {
		if item.Severity == Blocking {
			out = append(out, item)
		}
	}
	return out
}

// Err convertit les constats bloquants en une erreur unique, ou nil s'il n'y
// en a aucun. C'est la forme attendue par les gardes d'exécution.
func (f Findings) Err() error {
	blocking := f.Blocking()
	if len(blocking) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(blocking))
	for _, item := range blocking {
		msgs = append(msgs, item.String())
	}
	return fmt.Errorf("non-conformité ETSI: %s", strings.Join(msgs, " ; "))
}

// Advisories retourne les constats non bloquants, destinés à être journalisés.
func (f Findings) Advisories() Findings {
	var out Findings
	for _, item := range f {
		if item.Severity == Advisory {
			out = append(out, item)
		}
	}
	return out
}

func fail(req Requirement, format string, args ...any) Finding {
	return Finding{Requirement: req, Severity: Blocking, Detail: fmt.Sprintf(format, args...)}
}

func warn(req Requirement, format string, args ...any) Finding {
	return Finding{Requirement: req, Severity: Advisory, Detail: fmt.Sprintf(format, args...)}
}

// Status qualifie, dans la matrice de conformité, l'état d'une exigence pour
// l'ensemble du système. Trois valeurs seulement, pour qu'aucune zone grise ne
// puisse s'y loger.
type Status string

const (
	// StatusCovered : l'exigence est appliquée par du code de ce dépôt et
	// vérifiée par un test.
	StatusCovered Status = "couvert"
	// StatusGap : écart connu et assumé, avec une mesure compensatoire et une
	// cible identifiée.
	StatusGap Status = "écart documenté"
	// StatusOutOfScope : exigence organisationnelle, qu'aucun logiciel ne peut
	// satisfaire seul.
	StatusOutOfScope Status = "hors périmètre logiciel"
)

// Entry est une ligne de la matrice de conformité : une exigence, le mécanisme
// qui la porte, le test qui le vérifie, et son statut.
type Entry struct {
	Requirement Requirement
	Status      Status
	// Mechanism nomme le code qui applique l'exigence (chemin de fichier ou
	// mesure décrite), ou la mesure compensatoire pour un écart.
	Mechanism string
	// Test nomme le test exécutable qui vérifie le mécanisme. Vide pour les
	// exigences hors périmètre logiciel.
	Test string
	// Target décrit ce qui reste à faire pour lever un écart. Vide si couvert.
	Target string
}

// Matrix est la matrice de conformité complète du système.
type Matrix []Entry

// Counts résume la matrice par statut.
func (m Matrix) Counts() map[Status]int {
	out := map[Status]int{StatusCovered: 0, StatusGap: 0, StatusOutOfScope: 0}
	for _, e := range m {
		out[e.Status]++
	}
	return out
}

// Standards liste les normes citées par la matrice, dans l'ordre alphabétique.
func (m Matrix) Standards() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range m {
		if !seen[e.Requirement.Standard] {
			seen[e.Requirement.Standard] = true
			out = append(out, e.Requirement.Standard)
		}
	}
	sort.Strings(out)
	return out
}

// Validate contrôle la cohérence interne de la matrice : toute exigence
// déclarée couverte doit nommer un mécanisme et un test, tout écart doit
// nommer une mesure compensatoire et une cible. C'est ce qui empêche la
// matrice de se vider de son sens au fil des modifications.
func (m Matrix) Validate() error {
	var problems []string
	seen := map[string]bool{}
	for _, e := range m {
		key := e.Requirement.String()
		if seen[key] {
			problems = append(problems, fmt.Sprintf("%s: exigence déclarée deux fois", key))
		}
		seen[key] = true

		switch e.Status {
		case StatusCovered:
			if e.Mechanism == "" {
				problems = append(problems, fmt.Sprintf("%s: couvert mais aucun mécanisme nommé", key))
			}
			if e.Test == "" {
				problems = append(problems, fmt.Sprintf("%s: couvert mais aucun test nommé", key))
			}
		case StatusGap:
			if e.Mechanism == "" {
				problems = append(problems, fmt.Sprintf("%s: écart sans mesure compensatoire", key))
			}
			if e.Target == "" {
				problems = append(problems, fmt.Sprintf("%s: écart sans cible de levée", key))
			}
		case StatusOutOfScope:
			if e.Target == "" {
				problems = append(problems, fmt.Sprintf("%s: hors périmètre sans mesure attendue", key))
			}
		default:
			problems = append(problems, fmt.Sprintf("%s: statut inconnu %q", key, e.Status))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("matrice de conformité incohérente: %s", strings.Join(problems, " ; "))
	}
	return nil
}

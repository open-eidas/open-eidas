package conformance

import (
	"encoding/json"
	"fmt"
	"io"
)

// Report est la forme publiable de la matrice : celle que servent
// `/api/v1/conformance` et la sous-commande `conformance` des trois binaires.
//
// Elle est produite depuis SystemMatrix() et non recopiée : une instance qui
// tourne rend exactement la matrice que son code applique, ce qui permet à un
// auditeur de comparer le document du dépôt à ce que le service déclare
// réellement.
type Report struct {
	Version     string         `json:"version"`
	Comptes     map[string]int `json:"comptes"`
	Normes      []string       `json:"normes"`
	Exigences   []ReportEntry  `json:"exigences"`
	Cohérente   bool           `json:"matrice_coherente"`
	Incohérence string         `json:"incoherence,omitempty"`
}

// ReportEntry est une ligne de la matrice sous forme publiable.
type ReportEntry struct {
	Norme     string `json:"norme"`
	Clause    string `json:"clause"`
	Exigence  string `json:"exigence"`
	Statut    string `json:"statut"`
	Mécanisme string `json:"mecanisme,omitempty"`
	Test      string `json:"test,omitempty"`
	Cible     string `json:"cible,omitempty"`
}

// NewReport construit le rapport de conformité du système.
func NewReport(version string) Report {
	m := SystemMatrix()
	rep := Report{Version: version, Comptes: map[string]int{}, Normes: m.Standards()}
	for status, n := range m.Counts() {
		rep.Comptes[string(status)] = n
	}
	for _, e := range m {
		rep.Exigences = append(rep.Exigences, ReportEntry{
			Norme: e.Requirement.Standard, Clause: e.Requirement.Clause,
			Exigence: e.Requirement.Title, Statut: string(e.Status),
			Mécanisme: e.Mechanism, Test: e.Test, Cible: e.Target,
		})
	}
	if err := m.Validate(); err != nil {
		rep.Incohérence = err.Error()
	} else {
		rep.Cohérente = true
	}
	return rep
}

// WriteReport écrit le rapport et retourne une erreur si la matrice est
// incohérente, de sorte qu'une sous-commande `conformance` sorte en échec —
// c'est ce qui fait échouer la CI avant que le document publié ne perde son
// sens.
func WriteReport(w io.Writer, summary io.Writer, version string, markdown bool) error {
	m := SystemMatrix()
	if markdown {
		if _, err := io.WriteString(w, RenderMarkdown(m)); err != nil {
			return err
		}
	} else {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(NewReport(version)); err != nil {
			return err
		}
	}
	if err := m.Validate(); err != nil {
		return err
	}
	counts := m.Counts()
	_, err := fmt.Fprintf(summary,
		"\n%d exigences : %d couvertes, %d écarts documentés, %d hors périmètre logiciel.\n",
		len(m), counts[StatusCovered], counts[StatusGap], counts[StatusOutOfScope])
	return err
}

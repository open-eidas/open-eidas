package conformance

import (
	"strings"
	"testing"
)

// La matrice n'a de valeur que si elle ne peut pas se vider de son sens :
// une exigence déclarée couverte doit nommer le code qui l'applique et le
// test qui le vérifie, un écart doit nommer sa cible. Ce test est ce qui
// empêche une ligne d'être ajoutée « pour faire nombre ».
func TestSystemMatrixEstCoherente(t *testing.T) {
	if err := SystemMatrix().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefuseUneLigneCreuse(t *testing.T) {
	cas := []struct {
		nom     string
		entrée  Entry
		attendu string
	}{
		{
			nom: "couvert sans test",
			entrée: Entry{
				Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§1", Title: "t"},
				Status:      StatusCovered, Mechanism: "du code",
			},
			attendu: "aucun test nommé",
		},
		{
			nom: "couvert sans mécanisme",
			entrée: Entry{
				Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§1", Title: "t"},
				Status:      StatusCovered, Test: "un test",
			},
			attendu: "aucun mécanisme nommé",
		},
		{
			nom: "écart sans cible",
			entrée: Entry{
				Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§1", Title: "t"},
				Status:      StatusGap, Mechanism: "une mesure",
			},
			attendu: "sans cible de levée",
		},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			err := Matrix{c.entrée}.Validate()
			if err == nil {
				t.Fatal("une ligne creuse doit être refusée")
			}
			if !strings.Contains(err.Error(), c.attendu) {
				t.Errorf("message inattendu: %v", err)
			}
		})
	}
}

func TestValidateRefuseUneExigenceEnDouble(t *testing.T) {
	e := Entry{
		Requirement: Requirement{Standard: "ETSI EN 319 401", Clause: "§1", Title: "t"},
		Status:      StatusCovered, Mechanism: "du code", Test: "un test",
	}
	if err := (Matrix{e, e}).Validate(); err == nil {
		t.Fatal("une exigence déclarée deux fois doit être refusée")
	}
}

// Le document publié est rendu depuis la matrice : ce test vérifie qu'aucune
// exigence n'est perdue en chemin.
func TestRenderMarkdownCiteChaqueExigence(t *testing.T) {
	m := SystemMatrix()
	rendu := RenderMarkdown(m)
	for _, e := range m {
		if !strings.Contains(rendu, cell(e.Requirement.Title)) {
			t.Errorf("exigence absente du document rendu: %s", e.Requirement)
		}
	}
	for _, standard := range m.Standards() {
		if !strings.Contains(rendu, "## "+standard) {
			t.Errorf("norme absente du document rendu: %s", standard)
		}
	}
}

func TestFindingsErrNeRetientQueLeBloquant(t *testing.T) {
	f := Findings{
		warn(ReqRevocationReason, "avertissement"),
	}
	if err := f.Err(); err != nil {
		t.Fatalf("un avertissement seul ne doit pas produire d'erreur: %v", err)
	}
	f = append(f, fail(ReqKeyLength, "clé trop courte"))
	if err := f.Err(); err == nil {
		t.Fatal("un constat bloquant doit produire une erreur")
	} else if strings.Contains(err.Error(), "avertissement") {
		t.Errorf("l'erreur ne doit rapporter que le bloquant: %v", err)
	}
}

package replicate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReplicatePutsAuthenticatedContent(t *testing.T) {
	var gotPath, gotUser, gotPass string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("méthode attendue PUT, obtenue %s", r.Method)
		}
		gotPath = r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client, err := New(Options{URL: srv.URL + "/backups/", Username: "alice", Password: "secret", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("contenu du journal d'audit")
	result, err := client.Replicate(context.Background(), "audit-2026.log", content)
	if err != nil {
		t.Fatalf("réplication échouée: %v", err)
	}

	if gotPath != "/backups/audit-2026.log" {
		t.Errorf("chemin attendu /backups/audit-2026.log, obtenu %s", gotPath)
	}
	if gotUser != "alice" || gotPass != "secret" {
		t.Errorf("authentification incorrecte: user=%q pass=%q", gotUser, gotPass)
	}
	if string(gotBody) != string(content) {
		t.Errorf("contenu transmis incorrect: %q", gotBody)
	}
	if result.Bytes != len(content) {
		t.Errorf("taille rapportée incorrecte: %d", result.Bytes)
	}
}

func TestReplicateFailsOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := New(Options{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Replicate(context.Background(), "audit.log", []byte("x")); err == nil {
		t.Fatal("un refus HTTP du serveur distant doit être remonté comme une erreur")
	}
}

func TestNewRejectsMissingURL(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("une URL vide doit être refusée")
	}
}

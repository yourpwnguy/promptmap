package config_test

import (
	"testing"

	"github.com/promptmap/promptmap/internal/config"
)

func base() config.Config {
	c := config.Defaults()
	c.Target.URL = "https://app.example.com/api/chat"
	c.Target.BodyTemplate = `{"message": "{{PROMPT}}"}`
	return c
}

func TestValidateOK(t *testing.T) {
	if err := config.Validate(base()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateMissingPlaceholder(t *testing.T) {
	c := base()
	c.Target.BodyTemplate = `{"message": "hi"}`
	if err := config.Validate(c); err == nil {
		t.Fatal("expected error for missing {{PROMPT}}")
	}
}

func TestValidatePrivateBlocked(t *testing.T) {
	c := base()
	c.Target.URL = "http://localhost:8080/api/chat"
	c.Target.BodyTemplate = `{"m": "{{PROMPT}}"}`
	if err := config.Validate(c); err == nil {
		t.Fatal("expected refusal for localhost without allow_private")
	}
	c.Scan.AllowPrivate = true
	if err := config.Validate(c); err != nil {
		t.Fatalf("expected allow with flag, got %v", err)
	}
}

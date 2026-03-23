package vault

import (
	"strings"
	"testing"
)

func TestGeneratePassword_Length(t *testing.T) {
	pw, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error: %v", err)
	}
	if len(pw) != passwordLength {
		t.Errorf("password length = %d, want %d", len(pw), passwordLength)
	}
}

func TestGeneratePassword_Alphabet(t *testing.T) {
	for i := 0; i < 100; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error: %v", err)
		}
		for _, c := range pw {
			if !strings.ContainsRune(passwordAlphabet, c) {
				t.Errorf("password contains invalid character %q", c)
			}
		}
	}
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error: %v", err)
		}
		if seen[pw] {
			t.Errorf("duplicate password generated: %q", pw)
		}
		seen[pw] = true
	}
}

func TestValidatePath_Valid(t *testing.T) {
	if err := validatePath("kv/data/nomad/default/mc-test"); err != nil {
		t.Errorf("validatePath() unexpected error: %v", err)
	}
}

func TestValidatePath_Invalid(t *testing.T) {
	cases := []string{
		"kv/data/other/mc-test",
		"kv/metadata/nomad/default/mc-test",
		"secret/data/mc-test",
		"",
		"../kv/data/nomad/default/mc-test",
	}
	for _, path := range cases {
		if err := validatePath(path); err == nil {
			t.Errorf("validatePath(%q) expected error, got nil", path)
		}
	}
}

func TestValidateMetadataPath_Valid(t *testing.T) {
	if err := validateMetadataPath("kv/metadata/nomad/default/mc-test"); err != nil {
		t.Errorf("validateMetadataPath() unexpected error: %v", err)
	}
}

func TestValidateMetadataPath_Invalid(t *testing.T) {
	cases := []string{
		"kv/data/nomad/default/mc-test",
		"kv/metadata/other/mc-test",
		"",
	}
	for _, path := range cases {
		if err := validateMetadataPath(path); err == nil {
			t.Errorf("validateMetadataPath(%q) expected error, got nil", path)
		}
	}
}

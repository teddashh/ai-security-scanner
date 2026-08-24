package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time {
	return time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
}

func validScope(engine string) scopeDocument {
	provider := "microsoft365"
	expires := fixedNow().Add(30 * time.Minute).Format(time.RFC3339)
	return scopeDocument{
		SchemaVersion: "1",
		EngineID:      engine,
		GeneratedAt:   fixedNow().Format(time.RFC3339),
		Assets: []scopeAsset{{
			ID:       "asset-tenant-1",
			Name:     "Example tenant",
			Kind:     "tenant",
			Provider: &provider,
			Identifiers: []identifier{{
				Namespace: "microsoft365_tenant_id",
				Value:     "11111111-1111-1111-1111-111111111111",
			}},
			Grants: []scopeGrant{
				{ID: "grant-1", Permission: "inventory_read", ConfirmedBy: "operator", ConfirmedAt: fixedNow().Format(time.RFC3339), ExpiresAt: &expires, ExternalScope: json.RawMessage("null")},
				{ID: "grant-2", Permission: "configuration_read", ConfirmedBy: "operator", ConfirmedAt: fixedNow().Format(time.RFC3339), ExpiresAt: &expires, ExternalScope: json.RawMessage("null")},
			},
		}},
	}
}

func writeJSON(t *testing.T, name string, value any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScopeAcceptsExactlyOneReadOnlyMicrosoftTenant(t *testing.T) {
	for _, engine := range []string{"scubagear", "maester"} {
		path := writeJSON(t, "scope.json", validScope(engine))
		if _, err := loadScope(path, engine, fixedNow()); err != nil {
			t.Fatalf("%s scope rejected: %v", engine, err)
		}
	}
}

func TestScopeRejectsBroadOrActiveAuthority(t *testing.T) {
	tests := map[string]func(*scopeDocument){
		"multiple tenants": func(scope *scopeDocument) { scope.Assets = append(scope.Assets, scope.Assets[0]) },
		"wrong provider":   func(scope *scopeDocument) { value := "azure"; scope.Assets[0].Provider = &value },
		"admin grant":      func(scope *scopeDocument) { scope.Assets[0].Grants[0].Permission = "global_administrator" },
		"active scope": func(scope *scopeDocument) {
			scope.Assets[0].Grants[0].ExternalScope = json.RawMessage(`{"target":"example.com"}`)
		},
		"missing configuration": func(scope *scopeDocument) { scope.Assets[0].Grants = scope.Assets[0].Grants[:1] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			scope := validScope("maester")
			mutate(&scope)
			path := writeJSON(t, "scope.json", scope)
			if _, err := loadScope(path, "maester", fixedNow()); err == nil {
				t.Fatal("unsafe scope was accepted")
			}
		})
	}
}

func TestCredentialChannelRequiresOneFreshGraphToken(t *testing.T) {
	valid := credentialEnvelope{
		SchemaVersion: "1.0.0",
		Credentials: []credentialEntry{{
			Key:       "MSGRAPH_ACCESS_TOKEN",
			Value:     "protected-token-value",
			ExpiresAt: fixedNow().Add(30 * time.Minute),
			Source:    "external_read_only_grant",
		}},
	}
	if err := validateCredentials(writeJSON(t, "credential.json", valid), fixedNow()); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}

	mutations := map[string]func(*credentialEnvelope){
		"admin key":         func(value *credentialEnvelope) { value.Credentials[0].Key = "GLOBAL_ADMIN_TOKEN" },
		"expired":           func(value *credentialEnvelope) { value.Credentials[0].ExpiresAt = fixedNow().Add(-time.Second) },
		"long lived":        func(value *credentialEnvelope) { value.Credentials[0].ExpiresAt = fixedNow().Add(2 * time.Hour) },
		"unverified source": func(value *credentialEnvelope) { value.Credentials[0].Source = "user_environment" },
		"multiple":          func(value *credentialEnvelope) { value.Credentials = append(value.Credentials, value.Credentials[0]) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Credentials = append([]credentialEntry(nil), valid.Credentials...)
			mutate(&candidate)
			if err := validateCredentials(writeJSON(t, "credential.json", candidate), fixedNow()); err == nil {
				t.Fatal("unsafe credential was accepted")
			}
		})
	}
}

func TestInvocationIsFixedAndNeverCarriesCredentialMaterial(t *testing.T) {
	for _, engine := range []string{"scubagear", "maester"} {
		plan, err := fixedInvocation(engine, []string{
			"MSGRAPH_ACCESS_TOKEN=must-not-survive",
			"HTTPS_PROXY=socks5h://10.0.0.2:1080",
			"UNRELATED_SECRET=must-not-survive",
		})
		if err != nil {
			t.Fatal(err)
		}
		serialized := strings.Join(append(append([]string{}, plan.Args...), plan.Env...), "\n")
		if strings.Contains(serialized, "must-not-survive") || strings.Contains(serialized, "MSGRAPH_ACCESS_TOKEN") || strings.Contains(serialized, "UNRELATED_SECRET") {
			t.Fatal("credential or unrelated environment leaked into the child")
		}
		if !strings.Contains(serialized, "HTTPS_PROXY=socks5h://10.0.0.2:1080") {
			t.Fatal("managed egress proxy was not preserved")
		}
		if plan.Program != powershell || plan.Args[len(plan.Args)-2] != "-File" || !strings.HasSuffix(plan.Args[len(plan.Args)-1], "run-"+engine+".ps1") {
			t.Fatalf("unexpected fixed plan: %#v", plan)
		}
	}
	if _, err := fixedInvocation("powershell", nil); err == nil {
		t.Fatal("unallowlisted engine was accepted")
	}
}

func TestBoundedReaderRejectsSymlinksAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("12345"), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(link, 100); err == nil {
		t.Fatal("symlink was accepted")
	}
	if _, err := readBoundedRegularFile(target, 4); err == nil {
		t.Fatal("oversized file was accepted")
	}
}

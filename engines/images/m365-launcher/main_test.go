package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
		parent := []string{
			"MSGRAPH_ACCESS_TOKEN=must-not-survive",
			"UNRELATED_SECRET=must-not-survive",
			"NO_PROXY=",
		}
		for _, key := range []string{"AI_SECURITY_SCANNER_PROXY", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
			parent = append(parent, key+"=socks5h://10.0.0.2:1080")
		}
		plan, err := fixedInvocation(engine, parent)
		if err != nil {
			t.Fatal(err)
		}
		serialized := strings.Join(append(append([]string{}, plan.Args...), plan.Env...), "\n")
		if strings.Contains(serialized, "must-not-survive") || strings.Contains(serialized, "MSGRAPH_ACCESS_TOKEN") || strings.Contains(serialized, "UNRELATED_SECRET") {
			t.Fatal("credential or unrelated environment leaked into the child")
		}
		// PowerShell reads the gateway from the proxy variables in the
		// spelling .NET recognises; the gateway itself is unchanged.
		for _, entry := range []string{
			"AI_SECURITY_SCANNER_PROXY=socks5h://10.0.0.2:1080", "NO_PROXY=",
			"ALL_PROXY=socks5://10.0.0.2:1080", "all_proxy=socks5://10.0.0.2:1080",
			"HTTP_PROXY=socks5://10.0.0.2:1080", "http_proxy=socks5://10.0.0.2:1080",
			"HTTPS_PROXY=socks5://10.0.0.2:1080", "https_proxy=socks5://10.0.0.2:1080",
		} {
			if !slices.Contains(plan.Env, entry) {
				t.Fatalf("managed egress proxy entry %q is missing from %v", entry, plan.Env)
			}
		}
		if plan.Program != powershell || plan.Args[len(plan.Args)-2] != "-File" || !strings.HasSuffix(plan.Args[len(plan.Args)-1], "run-"+engine+".ps1") {
			t.Fatalf("unexpected fixed plan: %#v", plan)
		}
	}
	if _, err := fixedInvocation("powershell", nil); err == nil {
		t.Fatal("unallowlisted engine was accepted")
	}
	for _, malformed := range []string{
		"", "socks5h://gateway:1080", "socks5://10.0.0.2:1080", "socks5h://10.0.0.2:1081",
		"socks5h://user@10.0.0.2:1080", "http://10.0.0.2:1080", "socks5h://10.0.0.2:1080/path",
	} {
		if _, err := fixedInvocation("scubagear", []string{"AI_SECURITY_SCANNER_PROXY=" + malformed}); err == nil {
			t.Fatalf("malformed managed gateway %q was accepted", malformed)
		}
	}
}

func TestRuntimeDirectoriesExistBeforePowerShellStarts(t *testing.T) {
	plan, err := fixedInvocation("maester", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		index := slices.IndexFunc(plan.Env, func(entry string) bool { return strings.HasPrefix(entry, key+"=") })
		if index < 0 || !slices.Contains(runtimeDirectories, strings.TrimPrefix(plan.Env[index], key+"=")) {
			t.Fatalf("%s is not one of the directories the launcher creates: %v", key, plan.Env)
		}
	}
	root := t.TempDir()
	directories := []string{filepath.Join(root, "tmp", "home"), filepath.Join(root, "tmp", "cache")}
	if err := prepareRuntimeDirectories(directories); err != nil {
		t.Fatal(err)
	}
	for _, directory := range directories {
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("runtime directory %s was not created private: %v %v", directory, info, err)
		}
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

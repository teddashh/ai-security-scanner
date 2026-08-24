package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProviderRequiresExactCredentialClosure(t *testing.T) {
	aws := map[string]string{
		"AWS_ACCESS_KEY_ID":     "id",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "token",
	}
	if selected, err := providerFromCredentialKeys(aws); err != nil || selected != providerAWS {
		t.Fatalf("AWS credential closure rejected: %v", err)
	}
	aws["AZURE_ACCESS_TOKEN"] = "mixed"
	if _, err := providerFromCredentialKeys(aws); err == nil {
		t.Fatal("mixed provider credentials were accepted")
	}
}

func TestScopeRejectsUnknownFieldsAndExpiredGrants(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "scope.json")
	expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	scope := map[string]any{
		"schema_version": "1",
		"engine_id":      "prowler",
		"generated_at":   time.Now().UTC().Format(time.RFC3339Nano),
		"assets": []any{map[string]any{
			"id": "asset", "name": "account", "kind": "cloud_account", "provider": "aws",
			"region": nil, "identifiers": []any{},
			"grants": []any{map[string]any{
				"id": "grant", "permission": "inventory_read", "confirmed_by": "tester",
				"confirmed_at": time.Now().UTC().Format(time.RFC3339Nano), "expires_at": expired,
				"authorization_reference": nil, "external_scope": nil,
			}},
		}},
	}
	bytes, _ := json.Marshal(scope)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := loadScope(path, "prowler")
	if err != nil {
		t.Fatalf("parse scope: %v", err)
	}
	if err := validateScopePermissions(document, "prowler"); err == nil {
		t.Fatal("expired scope grant was accepted")
	}
	scope["unexpected"] = true
	bytes, _ = json.Marshal(scope)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path, "prowler"); err == nil {
		t.Fatal("unknown scope field was accepted")
	}
}

func TestChildEnvironmentDropsAmbientSecrets(t *testing.T) {
	t.Setenv("AWS_PROFILE", "must-not-pass")
	t.Setenv("PROWLER_CLOUD_API_KEY", "must-not-pass")
	t.Setenv("HTTPS_PROXY", "socks5h://gateway:1080")
	environment := childEnvironment(map[string]string{
		"AWS_ACCESS_KEY_ID":     "id",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "token",
	}, providerAWS, "/tmp/private")
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	if strings.Contains(joined, "AWS_PROFILE=") || strings.Contains(joined, "PROWLER_CLOUD_API_KEY=") {
		t.Fatal("ambient secret escaped into child environment")
	}
	if !strings.Contains(joined, "\nHTTPS_PROXY=socks5h://gateway:1080\n") {
		t.Fatal("managed proxy was not preserved")
	}
	if !strings.Contains(joined, "\nAWS_MAX_ATTEMPTS=2\n") ||
		!strings.Contains(joined, "\nAWS_RETRY_MODE=standard\n") {
		t.Fatal("AWS retries are not statically bounded")
	}
}

func TestRunCommandToFileBoundsAndCleansOutput(t *testing.T) {
	directory := t.TempDir()
	success := filepath.Join(directory, "success.json")
	if err := runCommandToFile(invocation{Program: "/bin/echo", Args: []string{"evidence"}}, success); err != nil {
		t.Fatalf("capture successful output: %v", err)
	}
	content, err := os.ReadFile(success)
	if err != nil || string(content) != "evidence\n" {
		t.Fatalf("unexpected captured output %q: %v", content, err)
	}

	failure := filepath.Join(directory, "failure.json")
	if err := runCommandToFile(invocation{Program: "/bin/false"}, failure); err == nil {
		t.Fatal("failed child process was accepted")
	}
	if _, err := os.Lstat(failure); !os.IsNotExist(err) {
		t.Fatal("incomplete evidence file was not removed")
	}

	boundedPath := filepath.Join(directory, "bounded")
	file, err := os.OpenFile(boundedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := &boundedOutputWriter{file: file, remaining: 3}
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("d")); err == nil || !writer.exceeded {
		t.Fatal("bounded writer accepted excess output")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReleasedScopeFixturesMatchLauncherContract(t *testing.T) {
	for _, engineID := range []string{"cloudquery", "steampipe", "prowler", "scoutsuite", "cloudsplaining"} {
		t.Run(engineID, func(t *testing.T) {
			document, err := loadScope(filepath.Join("testdata", "scope-"+engineID+".json"), engineID)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			if err := validateScopePermissions(document, engineID); err != nil {
				t.Fatalf("validate fixture permissions: %v", err)
			}
			if err := validateProviderForEngine(engineID, providerAWS, document); err != nil {
				t.Fatalf("validate fixture provider: %v", err)
			}
		})
	}
}

func TestCloudQueryConfigurationIsExactLocalSourceClosure(t *testing.T) {
	config := string(cloudQueryConfiguration())
	tables := []string{
		"aws_iam_accounts",
		"aws_iam_credential_reports",
		"aws_iam_groups",
		"aws_iam_password_policies",
		"aws_iam_policies",
		"aws_iam_roles",
		"aws_iam_users",
	}
	for _, table := range tables {
		if strings.Count(config, "\n    - "+table+"\n") != 1 {
			t.Fatalf("fixed CloudQuery table %s is missing or duplicated", table)
		}
	}
	if strings.Count(config, "\n    - aws_") != len(tables) {
		t.Fatal("CloudQuery profile contains a table outside the exact allowlist")
	}
	for _, required := range []string{
		"path: /usr/local/libexec/cloudquery-source-aws",
		"path: /usr/local/libexec/cloudquery-destination-file",
		"registry: local",
		"regions: [us-east-1]",
		"directory: /output",
		"format: json",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("CloudQuery config lacks %q", required)
		}
	}
	for _, forbidden := range []string{
		"aws_iam_account_authorization_details",
		"cloudquery/aws",
		"cloudquery/file",
		"registry: grpc",
		"registry: github",
		"registry: cloudquery",
		"{{TABLE}}",
		"{{UUID}}",
	} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("CloudQuery config contains forbidden registry or schema value %q", forbidden)
		}
	}
}

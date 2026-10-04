package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFixedInvocationIsOnlyNativeStaticExport(t *testing.T) {
	want := []string{"-I", "-B", "-m", "agentic_radar", "scan", "langgraph", "--input-dir", "/workspace", "--export-graph-json", "--output-file", reportPath}
	if got := fixedArguments("langgraph"); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected native invocation: %#v", got)
	}
	for _, arguments := range [][]string{
		{"--engine", engineID, "--workspace", workspaceMountPath, "--output", outputMountPath, "--harden-prompts"},
		{"--engine", engineID, "--workspace", workspaceMountPath, "--output", outputMountPath, "test"},
		{"--engine", engineID, "--workspace", "/host", "--output", outputMountPath},
	} {
		if err := run(arguments); err == nil {
			t.Fatalf("accepted caller-controlled arguments: %v", arguments)
		}
	}
}

func fixtureScope() scopeDocument {
	return scopeDocument{SchemaVersion: "1", EngineID: engineID, GeneratedAt: "2026-10-04T00:00:00Z", Assets: []scopeAsset{{ID: "asset-1", Kind: "repository", Identifiers: []scopeIdentifier{{Namespace: workspaceSHA256Namespace, Value: strings.Repeat("a", 64)}, {Namespace: frameworkNamespace, Value: "langgraph"}}, Grants: []scopeGrant{{ID: "grant-1", Permission: "local_artifact_read", ConfirmedBy: "controlled fixture", ConfirmedAt: "2026-01-01T00:00:00Z"}}}}}
}

func TestSelectionRequiresOneFrameworkAndExactLocalGrant(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*scopeDocument)
		valid  bool
	}{
		{"valid", func(*scopeDocument) {}, true},
		{"unsupported", func(d *scopeDocument) { d.Assets[0].Identifiers[1].Value = "--harden-prompts" }, false},
		{"duplicate", func(d *scopeDocument) {
			d.Assets[0].Identifiers = append(d.Assets[0].Identifiers, d.Assets[0].Identifiers[1])
		}, false},
		{"missing", func(d *scopeDocument) { d.Assets[0].Identifiers = d.Assets[0].Identifiers[:1] }, false},
		{"multi-asset", func(d *scopeDocument) { d.Assets = append(d.Assets, d.Assets[0]) }, false},
		{"wrong engine", func(d *scopeDocument) { d.EngineID = "mcp-armor" }, false},
		{"wrong permission", func(d *scopeDocument) { d.Assets[0].Grants[0].Permission = "configuration_read" }, false},
		{"expired", func(d *scopeDocument) { v := "2020-01-01T00:00:00Z"; d.Assets[0].Grants[0].ExpiresAt = &v }, false},
		{"external scope", func(d *scopeDocument) { d.Assets[0].Grants[0].ExternalScope = json.RawMessage(`{}`) }, false},
	} {
		t.Run(change.name, func(t *testing.T) {
			document := fixtureScope()
			change.mutate(&document)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "scope.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readSelection(path)
			if (err == nil) != change.valid {
				t.Fatalf("framework %q error %v", got, err)
			}
		})
	}
}

func TestNativeEvidenceMustMatchFrozenFrameworkAndCompleteness(t *testing.T) {
	base := `{"schema_version":"1","scanner_version":"0.14.1","framework":"langgraph","status":"no_supported_workflow","complete":true,"warnings":[],"graph":{"nodes":[],"edges":[],"agents":[],"tools":[]}}`
	for _, change := range []struct {
		name     string
		report   string
		expected string
		valid    bool
	}{
		{"empty inventory", base, "langgraph", true},
		{"wrong frozen framework", base, "n8n", false},
		{"wrong scanner", strings.Replace(base, "0.14.1", "0.15.0", 1), "langgraph", false},
		{"missing collection", strings.Replace(base, `"tools":[]`, `"tools":null`, 1), "langgraph", false},
		{"contradictory status", strings.Replace(base, "no_supported_workflow", "workflow_found", 1), "langgraph", false},
		{"warning without partial", strings.Replace(base, `"warnings":[]`, `"warnings":[{"code":"analyzer_diagnostic","message":"native diagnostic"}]`, 1), "langgraph", false},
		{"partial graph", strings.Replace(strings.Replace(base, `"warnings":[]`, `"warnings":[{"code":"analyzer_diagnostic","message":"native diagnostic"}]`, 1), `"complete":true`, `"complete":false`, 1), "langgraph", true},
		{"trailing", base + `{}`, "langgraph", false},
	} {
		t.Run(change.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(change.report), 0o600); err != nil {
				t.Fatal(err)
			}
			err := validateTerminalEvidence(path, change.expected)
			if (err == nil) != change.valid {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestEvidenceRejectsSymlinksAndExistingOutput(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openBoundedRegularFile(link, maxEvidenceBytes, "evidence"); err == nil {
		t.Fatal("accepted symlink evidence")
	}
	if err := ensureAbsent(target); err == nil {
		t.Fatal("accepted existing evidence")
	}
	if err := requireReadOnlyWorkspace(root); err == nil {
		t.Fatal("accepted writable workspace")
	}
}

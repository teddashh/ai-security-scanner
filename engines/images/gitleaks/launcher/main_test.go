package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFixedArgumentsOwnEveryPolicyAndOutputChoice(t *testing.T) {
	want := []string{
		"dir",
		"--config", configPath,
		"--ignore-gitleaks-allow",
		"--no-source-ignore",
		"--exit-code", "0",
		"--redact=100",
		"--max-decode-depth", "5",
		"--max-archive-depth", "0",
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-banner",
		"--no-color",
		workspaceMountPath,
	}
	if got := fixedArguments(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixed invocation changed:\n got %#v\nwant %#v", got, want)
	}
}

func TestRedactedEvidenceAcceptsOnlyRedactionSentinels(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.json")
	if err := os.WriteFile(valid, []byte(`[{"RuleID":"generic-api-key","Secret":"REDACTED","Match":"api_key = REDACTED"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRedactedEvidence(valid); err != nil {
		t.Fatalf("valid redacted evidence rejected: %v", err)
	}

	for name, payload := range map[string]string{
		"raw":      `[{"RuleID":"generic-api-key","Secret":"must-not-survive"}]`,
		"missing":  `[{"RuleID":"generic-api-key"}]`,
		"trailing": `[] {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateRedactedEvidence(path); err == nil {
				t.Fatal("unsafe evidence was accepted")
			}
		})
	}
}

func TestArgumentParserRejectsTargetControlledOptions(t *testing.T) {
	err := run([]string{"--workspace", workspaceMountPath, "--output", outputMountPath, "--config", "/workspace/.gitleaks.toml"})
	if err == nil || !strings.Contains(err.Error(), "static launcher contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

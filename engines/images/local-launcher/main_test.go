package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStaticPlansNeverUseShellNetworkOrUserArguments(t *testing.T) {
	cases := map[string]string{
		"semgrep": profileRepository, "trufflehog": profileRepository,
		"trivy": profileOCIImage, "grype": profileOCIImage,
		"kubescape": profileKubernetes, "kube-bench": profileNodeSnapshot,
	}
	for engineID, inputProfile := range cases {
		planned, err := planInvocation(engineID, inputProfile)
		if err != nil {
			t.Fatalf("plan %s: %v", engineID, err)
		}
		if !strings.HasPrefix(planned.program, "/usr/local/bin/") {
			t.Fatalf("%s program is not an absolute managed binary: %s", engineID, planned.program)
		}
		for _, token := range append([]string{planned.program}, planned.arguments...) {
			if strings.ContainsAny(token, "\x00\r\n") || strings.Contains(token, "$(") || strings.Contains(token, "${") {
				t.Fatalf("%s contains dynamic token %q", engineID, token)
			}
			if token == "sh" || token == "bash" || strings.HasSuffix(token, "/sh") || strings.HasSuffix(token, "/bash") {
				t.Fatalf("%s invokes a shell", engineID)
			}
		}
		for _, variable := range planned.environment {
			upper := strings.ToUpper(variable)
			if strings.Contains(upper, "TOKEN=") || strings.Contains(upper, "PASSWORD=") || strings.Contains(upper, "PROXY=") {
				t.Fatalf("%s child environment exposes network or credential variable %q", engineID, variable)
			}
		}
	}
}

func TestTruffleHogIsFilesystemOnlyAndCannotVerify(t *testing.T) {
	planned, err := planInvocation("trufflehog", profileRepository)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"filesystem", "/workspace", "--json", "--no-verification", "--no-verification-cache", "--no-update", "--concurrency", "4"}
	if !reflect.DeepEqual(planned.arguments, want) || !planned.stdoutIsOutput {
		t.Fatalf("unexpected TruffleHog boundary: %#v", planned)
	}
}

func TestKubescapeIsOfflineManifestOnly(t *testing.T) {
	planned, err := planInvocation("kubescape", profileKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(planned.arguments, " ")
	for _, required := range []string{"/workspace", "--use-from /opt/ai-security-scanner/kubescape-artifacts/nsa.json", "--keep-local", "--submit=false", "--host-scan=false"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Kubescape plan lacks %q: %s", required, joined)
		}
	}
}

func TestTypedContainerPlansUseOCIImageLayout(t *testing.T) {
	trivy, err := planInvocation("trivy", profileOCIImage)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"image", "--input", "/workspace",
		"--cache-dir", "/opt/ai-security-scanner/trivy-cache",
		"--cache-backend", "memory",
		"--skip-db-update", "--skip-java-db-update", "--offline-scan",
		"--pkg-types", "os", "--skip-version-check", "--disable-telemetry",
		"--skip-vex-repo-update", "--scanners", "vuln",
		"--format", "json", "--output", "/output/trivy.json",
	}
	if !reflect.DeepEqual(trivy.arguments, want) {
		t.Fatalf("Trivy OCI boundary drifted:\n got: %#v\nwant: %#v", trivy.arguments, want)
	}
	grype, err := planInvocation("grype", profileOCIImage)
	if err != nil {
		t.Fatal(err)
	}
	if grype.arguments[0] != "oci-dir:/workspace" {
		t.Fatalf("Grype did not use its fixed OCI layout source: %#v", grype.arguments)
	}
}

func TestTrivyFilesystemProfilesUseLibraryPackagesAndKeepTheImmutableDatabaseReadOnly(t *testing.T) {
	for _, profile := range []string{profileRepository, profileIaC} {
		planned, err := planInvocation("trivy", profile)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"filesystem", "--cache-dir", "/opt/ai-security-scanner/trivy-cache",
			"--cache-backend", "memory",
			"--skip-db-update", "--skip-java-db-update", "--offline-scan",
			"--pkg-types", "library", "--skip-version-check", "--disable-telemetry",
			"--skip-vex-repo-update", "--scanners", "vuln",
			"--format", "json", "--output", "/output/trivy.json", "/workspace",
		}
		if !reflect.DeepEqual(planned.arguments, want) {
			t.Fatalf("Trivy profile %s boundary drifted:\n got: %#v\nwant: %#v", profile, planned.arguments, want)
		}
	}
}

func TestEngineProfilesRejectCrossTypeExecution(t *testing.T) {
	for _, test := range []struct{ engine, profile string }{
		{"grype", profileRepository},
		{"kubescape", profileIaC},
		{"kube-bench", profileKubernetes},
		{"semgrep", profileOCIImage},
	} {
		if err := validateEngineInputProfile(test.engine, test.profile); err == nil {
			t.Fatalf("%s accepted incompatible profile %s", test.engine, test.profile)
		}
	}
}

func TestInputMarkerIsStrictAndRepositoryDefaultsOnlyWhenAbsent(t *testing.T) {
	root := t.TempDir()
	if profile, err := loadInputProfile(root); err != nil || profile != profileRepository {
		t.Fatalf("marker-free repository rejected: profile=%q err=%v", profile, err)
	}
	marker := `{"schema_version":"ai-security-scanner.local-input/v1","input_profile":"container_image_oci_layout"}`
	if err := os.WriteFile(filepath.Join(root, inputMarkerFilename), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if profile, err := loadInputProfile(root); err != nil || profile != profileOCIImage {
		t.Fatalf("valid OCI marker rejected: profile=%q err=%v", profile, err)
	}
	if err := os.WriteFile(filepath.Join(root, inputMarkerFilename), []byte(marker[:len(marker)-1]+`,"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInputProfile(root); err == nil {
		t.Fatal("unknown marker field was accepted")
	}
}

func TestNodeSnapshotRejectsUninventoriedAndAlteredFiles(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "kubelet-config.yaml")
	if err := os.WriteFile(config, []byte("kind: KubeletConfiguration\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(config)
	if err != nil {
		t.Fatal(err)
	}
	profile := `{"schema_version":"1.0.0","profile":"cis-kubernetes-node-config","captured_at":"2026-08-24T12:00:00Z","files":[{"path":"kubelet-config.yaml","sha256":"sha256:` + digest + `"}]}`
	if err := os.WriteFile(filepath.Join(root, "profile.json"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeSnapshot(root); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeSnapshot(root); err == nil {
		t.Fatal("uninventoried snapshot file was accepted")
	}
	if err := os.Remove(filepath.Join(root, "unexpected")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeSnapshot(root); err == nil {
		t.Fatal("altered snapshot file was accepted")
	}
}

func TestInvalidContractAndWritableWorkspaceFailClosed(t *testing.T) {
	if err := run([]string{"--engine", "unknown", "--workspace", workspaceMountPath, "--output", outputMountPath}); err == nil {
		t.Fatal("unknown engine was accepted")
	}
	if err := requireReadOnlyWorkspace(t.TempDir()); err == nil {
		t.Fatal("writable workspace was accepted")
	}
}

func TestSupportedEnginesAreExact(t *testing.T) {
	got := map[string]bool{}
	for _, id := range []string{"semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench"} {
		if !supportedEngine(id) {
			t.Fatalf("expected engine %s", id)
		}
		got[id] = true
	}
	want := []string{"grype", "kube-bench", "kubescape", "semgrep", "trivy", "trufflehog"}
	if !reflect.DeepEqual(sortedKeys(got), want) {
		t.Fatalf("unexpected engine set: %#v", sortedKeys(got))
	}
	if supportedEngine("gitleaks") || supportedEngine("") {
		t.Fatal("out-of-scope engine accepted")
	}
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := sha256Sum(data)
	return value, nil
}

func sha256Sum(value []byte) string {
	digest := sha256.New()
	_, _ = digest.Write(value)
	return hex.EncodeToString(digest.Sum(nil))
}

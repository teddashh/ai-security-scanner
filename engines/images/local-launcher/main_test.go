package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStaticPlansNeverUseShellNetworkOrUserArguments(t *testing.T) {
	cases := map[string]string{
		"semgrep": profileRepository, "trufflehog": profileRepository,
		"trivy": profileOCIImage, "grype": profileOCIImage,
		"kubescape": profileKubernetes, "kube-bench": profileNodeSnapshot,
	}
	for engineID, inputProfile := range cases {
		planned, err := planInvocations(engineID, inputProfile)
		if err != nil {
			t.Fatalf("plan %s: %v", engineID, err)
		}
		for _, item := range planned {
			if !strings.HasPrefix(item.program, "/usr/local/bin/") {
				t.Fatalf("%s program is not an absolute managed binary: %s", engineID, item.program)
			}
			for _, token := range append([]string{item.program}, item.arguments...) {
				if strings.ContainsAny(token, "\x00\r\n") || strings.Contains(token, "$(") || strings.Contains(token, "${") {
					t.Fatalf("%s contains dynamic token %q", engineID, token)
				}
				if token == "sh" || token == "bash" || strings.HasSuffix(token, "/sh") || strings.HasSuffix(token, "/bash") {
					t.Fatalf("%s invokes a shell", engineID)
				}
			}
			for _, variable := range item.environment {
				upper := strings.ToUpper(variable)
				if strings.Contains(upper, "TOKEN=") || strings.Contains(upper, "PASSWORD=") || strings.Contains(upper, "PROXY=") {
					t.Fatalf("%s child environment exposes network or credential variable %q", engineID, variable)
				}
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

func TestSemgrepUsesThePinnedOfflineRulePackWithResourceBounds(t *testing.T) {
	planned, err := planInvocation("semgrep", profileRepository)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(planned.arguments, " ")
	for _, required := range []string{
		"--config " + semgrepRulePackPath,
		"--metrics=off",
		"--disable-version-check",
		"--no-rewrite-rule-ids",
		"--oss-only",
		"--jobs 2",
		"--max-memory 2048",
		"--timeout 10",
		"--timeout-threshold 3",
		"--max-target-bytes 10000000",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Semgrep plan lacks %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--config auto", "--autofix", "--pro", "rules.yml"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Semgrep plan contains forbidden option %q: %s", forbidden, joined)
		}
	}
}

func TestSemgrepRulePackManifestRejectsTamperingAndUninventoriedFiles(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "python", "security", "first.yaml")
	second := filepath.Join(root, "typescript", "security", "second.yml")
	if err := os.MkdirAll(filepath.Dir(first), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(second), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstDigest, err := fileSHA256(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := fileSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	manifest := firstDigest + "  python/security/first.yaml\n" +
		secondDigest + "  typescript/security/second.yml\n"
	manifestPath := filepath.Join(t.TempDir(), "RULES.sha256")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := fileSHA256(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySemgrepRulePack(root, manifestPath, manifestDigest, 2); err != nil {
		t.Fatalf("valid Semgrep rule pack rejected: %v", err)
	}
	if err := os.WriteFile(first, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySemgrepRulePack(root, manifestPath, manifestDigest, 2); err == nil {
		t.Fatal("tampered Semgrep rule was accepted")
	}
	if err := os.WriteFile(first, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySemgrepRulePack(root, manifestPath, manifestDigest, 2); err == nil {
		t.Fatal("uninventoried Semgrep rule was accepted")
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

func TestGrypeRepositoryUsesTheUpstreamDirectoryCataloger(t *testing.T) {
	planned, err := planInvocation("grype", profileRepository)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dir:/workspace", "--output", "json", "--file", "/output/grype.json"}
	if !reflect.DeepEqual(planned.arguments, want) {
		t.Fatalf("Grype repository invocation drifted:\n got: %#v\nwant: %#v", planned.arguments, want)
	}
	if planned.stdoutIsOutput {
		t.Fatal("Grype repository evidence must use its fixed JSON output path")
	}
}

func TestTrivyFilesystemProfilesUseLibraryPackagesAndKeepTheImmutableDatabaseReadOnly(t *testing.T) {
	for _, profile := range []string{profileRepository, profileIaC} {
		planned, err := planInvocations("trivy", profile)
		if err != nil {
			t.Fatal(err)
		}
		if len(planned) != 2 {
			t.Fatalf("Trivy profile %s planned %d invocations; expected lockfile and individual-package passes", profile, len(planned))
		}
		wantFilesystem := []string{
			"filesystem", "--cache-dir", "/opt/ai-security-scanner/trivy-cache",
			"--cache-backend", "memory",
			"--skip-db-update", "--skip-java-db-update", "--offline-scan",
			"--pkg-types", "library", "--skip-version-check", "--disable-telemetry",
			"--skip-vex-repo-update", "--scanners", "vuln",
			"--format", "json", "--output", "/output/trivy.json", "/workspace",
		}
		if !reflect.DeepEqual(planned[0].arguments, wantFilesystem) {
			t.Fatalf("Trivy profile %s filesystem boundary drifted:\n got: %#v\nwant: %#v", profile, planned[0].arguments, wantFilesystem)
		}
		wantIndividualPackages := []string{
			"rootfs", "--cache-dir", "/opt/ai-security-scanner/trivy-cache",
			"--cache-backend", "memory",
			"--skip-db-update", "--skip-java-db-update", "--offline-scan",
			"--pkg-types", "library", "--skip-version-check", "--disable-telemetry",
			"--skip-vex-repo-update", "--scanners", "vuln",
			"--format", "json", "--output", "/output/trivy-individual-packages.json", "/workspace",
		}
		if !reflect.DeepEqual(planned[1].arguments, wantIndividualPackages) {
			t.Fatalf("Trivy profile %s individual-package boundary drifted:\n got: %#v\nwant: %#v", profile, planned[1].arguments, wantIndividualPackages)
		}
	}
}

func TestTrivyOCIProfileDoesNotAddAWorkingTreePackagePass(t *testing.T) {
	planned, err := planInvocations("trivy", profileOCIImage)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 1 || planned[0].arguments[0] != "image" {
		t.Fatalf("Trivy OCI boundary added an unintended working-tree pass: %#v", planned)
	}
}

func TestKubeBenchKeepsUpstreamRemediationInItsReport(t *testing.T) {
	planned, err := planInvocation("kube-bench", profileNodeSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, argument := range planned.arguments {
		if argument == "--noremediations" {
			t.Fatal("kube-bench remediation was suppressed before normalization")
		}
	}
	arguments := strings.Join(planned.arguments, "\n")
	if !strings.Contains(arguments, "--json") ||
		!strings.Contains(arguments, "--outputfile") ||
		!strings.Contains(arguments, "--benchmark\n"+nodeSnapshotBench) {
		t.Fatalf("kube-bench did not retain its bounded JSON report: %#v", planned.arguments)
	}
}

func TestEngineProfilesRejectCrossTypeExecution(t *testing.T) {
	for _, test := range []struct{ engine, profile string }{
		{"grype", profileIaC},
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
	writeValidNodeSnapshot(t, root)
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
	if err := os.WriteFile(filepath.Join(root, "kubelet-config.yaml"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeSnapshot(root); err == nil {
		t.Fatal("altered snapshot file was accepted")
	}
}

func TestNodeSnapshotToolsReplayOnlyValidatedFacts(t *testing.T) {
	root := t.TempDir()
	writeValidNodeSnapshot(t, root)
	var output bytes.Buffer
	if err := runSnapshotStat(root, []string{"-c", "permissions=%a", filepath.Join(root, "kubelet-config.yaml")}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "permissions=600\n" {
		t.Fatalf("unexpected stat output %q", output.String())
	}
	output.Reset()
	if err := runSnapshotStat(root, []string{"-c", "%U:%G", filepath.Join(root, "ca.crt")}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "root:root\n" {
		t.Fatalf("unexpected owner output %q", output.String())
	}
	output.Reset()
	if err := runSnapshotPS(root, []string{"-fC", "kubelet"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "--client-ca-file="+filepath.Join(root, "ca.crt")) ||
		strings.Contains(output.String(), "/etc/kubernetes/pki/ca.crt") {
		t.Fatalf("snapshot path was not mechanically replayed: %q", output.String())
	}
	for _, rejected := range [][]string{{"-aux"}, {"-fC", "unapproved"}, {"-C", "kubelet", "-o", "pid"}} {
		if err := runSnapshotPS(root, rejected, &output); err == nil {
			t.Fatalf("ps accepted arguments %#v", rejected)
		}
	}
	if err := runSnapshotStat(root, []string{"-c", "%s", filepath.Join(root, "ca.crt")}, &output); err == nil {
		t.Fatal("stat accepted an unapproved format")
	}
}

func writeValidNodeSnapshot(t *testing.T, root string) {
	t.Helper()
	contents := map[string][]byte{
		"kubelet-config.yaml": []byte("kind: KubeletConfiguration\n"),
		"kubelet.service":     []byte("ExecStart=/usr/bin/kubelet\n"),
		"kubelet.conf":        []byte("kind: Config\n"),
		"kube-proxy.yaml":     []byte("kind: KubeProxyConfiguration\n"),
		"ca.crt":              []byte("snapshot fixture\n"),
	}
	sourcePaths := map[string]string{
		"kubelet-config.yaml": "/var/lib/kubelet/config.yaml",
		"kubelet.service":     "/etc/systemd/system/kubelet.service",
		"kubelet.conf":        "/etc/kubernetes/kubelet.conf",
		"kube-proxy.yaml":     "/var/lib/kube-proxy/config.yaml",
		"ca.crt":              "/etc/kubernetes/pki/ca.crt",
	}
	paths := []string{"ca.crt", "kube-proxy.yaml", "kubelet-config.yaml", "kubelet.conf", "kubelet.service"}
	profile := nodeSnapshot{
		SchemaVersion: nodeSnapshotSchema,
		Profile:       nodeSnapshotProfile,
		Benchmark:     nodeSnapshotBench,
		CapturedAt:    time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		Processes: []nodeSnapshotProcess{
			{Name: "kubelet", Command: "/usr/bin/kubelet --client-ca-file=/etc/kubernetes/pki/ca.crt"},
			{Name: "kube-proxy", Command: "/usr/bin/kube-proxy --config=/var/lib/kube-proxy/config.yaml"},
		},
	}
	for _, path := range paths {
		if err := os.WriteFile(filepath.Join(root, path), contents[path], 0o600); err != nil {
			t.Fatal(err)
		}
		profile.Files = append(profile.Files, nodeSnapshotFile{
			Path: path, SourcePath: sourcePaths[path], SHA256: "sha256:" + sha256Sum(contents[path]),
			Mode: "600", Owner: "root", Group: "root",
		})
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "profile.json"), payload, 0o600); err != nil {
		t.Fatal(err)
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

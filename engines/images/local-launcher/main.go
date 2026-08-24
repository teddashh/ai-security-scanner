// ai-security-scanner-local-launcher is the non-shell capability boundary for
// managed, offline source, dependency, and Kubernetes snapshot scanners. It
// accepts only the scanner-owned mount contract and never forwards user input
// as command-line arguments.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	workspaceMountPath  = "/workspace"
	outputMountPath     = "/output"
	maxEvidenceBytes    = 512 * 1024 * 1024
	maxImmutableBytes   = 2 * 1024 * 1024 * 1024
	maxLogBytes         = 8 * 1024 * 1024
	maxSnapshotBytes    = 8 * 1024 * 1024
	maxSnapshotFiles    = 32
	linuxStatfsReadOnly = 1
)

type invocation struct {
	program        string
	arguments      []string
	environment    []string
	outputPath     string
	stdoutIsOutput bool
	timeout        time.Duration
}

type nodeSnapshot struct {
	SchemaVersion string             `json:"schema_version"`
	Profile       string             `json:"profile"`
	CapturedAt    time.Time          `json:"captured_at"`
	Files         []nodeSnapshotFile `json:"files"`
}

type nodeSnapshotFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type boundedWriter struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		writer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		writer.overflow = true
	}
	_, _ = writer.buffer.Write(value)
	return original, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "managed local engine launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-local-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engineID := flags.String("engine", "", "fixed engine identifier")
	workspace := flags.String("workspace", "", "read-only assessment snapshot")
	output := flags.String("output", "", "runtime-owned evidence directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if !supportedEngine(*engineID) {
		return errors.New("engine identifier is not allowlisted")
	}
	if *workspace != workspaceMountPath || *output != outputMountPath {
		return errors.New("workspace and output paths must use the runtime-owned mounts")
	}
	if err := validateDirectory(*workspace, "workspace"); err != nil {
		return err
	}
	if err := requireReadOnlyWorkspace(*workspace); err != nil {
		return err
	}
	if err := validateDirectory(*output, "output"); err != nil {
		return err
	}
	if err := verifyEngineInputs(*engineID, *workspace); err != nil {
		return err
	}

	planned, err := planInvocation(*engineID)
	if err != nil {
		return err
	}
	if err := ensureOutputAbsent(planned.outputPath); err != nil {
		return err
	}
	if err := execute(planned); err != nil {
		_ = os.Remove(planned.outputPath)
		return err
	}
	if err := validateEvidence(planned.outputPath, *engineID == "trufflehog"); err != nil {
		_ = os.Remove(planned.outputPath)
		return err
	}
	return os.Chmod(planned.outputPath, 0o600)
}

func supportedEngine(engineID string) bool {
	switch engineID {
	case "semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench":
		return true
	default:
		return false
	}
}

func validateDirectory(path string, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s directory: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s path must be a real directory", label)
	}
	return nil
}

func requireReadOnlyWorkspace(path string) error {
	if runtime.GOOS == "linux" {
		var filesystem syscall.Statfs_t
		if err := syscall.Statfs(path, &filesystem); err != nil {
			return fmt.Errorf("inspect workspace mount flags: %w", err)
		}
		if filesystem.Flags&linuxStatfsReadOnly == 0 {
			return errors.New("workspace mount is writable; refusing to scan")
		}
		return nil
	}

	// The packaged engines target Linux. Keep the write probe as a fail-closed
	// fallback for development builds on other Unix-like systems.
	probe := filepath.Join(path, fmt.Sprintf(".ai-security-scanner-write-probe-%d", os.Getpid()))
	file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			return nil
		}
		return fmt.Errorf("verify read-only workspace: %w", err)
	}
	_ = file.Close()
	_ = os.Remove(probe)
	return errors.New("workspace mount is writable; refusing to scan")
}

func ensureOutputAbsent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect evidence path: %w", err)
	}
	return fmt.Errorf("evidence path already exists (%s, mode %s)", path, info.Mode())
}

func planInvocation(engineID string) (invocation, error) {
	fixedEnvironment := []string{
		"HOME=/tmp/ai-security-scanner-home",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"NO_COLOR=1",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME=/tmp/ai-security-scanner-cache",
		"XDG_CONFIG_HOME=/tmp/ai-security-scanner-config",
	}
	result := invocation{environment: fixedEnvironment, timeout: time.Hour}
	switch engineID {
	case "semgrep":
		result.program = "/usr/local/bin/semgrep"
		result.outputPath = "/output/semgrep.json"
		result.arguments = []string{
			"scan", "--json", "--output", result.outputPath,
			"--config", "/opt/ai-security-scanner/semgrep/rules.yml",
			"--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids",
			"--max-target-bytes", "10000000", "/workspace",
		}
		result.environment = append(result.environment,
			"SEMGREP_ENABLE_VERSION_CHECK=0", "SEMGREP_SEND_METRICS=off")
	case "trufflehog":
		result.program = "/usr/local/bin/trufflehog"
		result.outputPath = "/output/trufflehog.jsonl"
		result.stdoutIsOutput = true
		result.arguments = []string{
			"filesystem", "/workspace", "--json", "--no-verification",
			"--no-verification-cache", "--no-update", "--concurrency", "4",
		}
	case "trivy":
		result.program = "/usr/local/bin/trivy"
		result.outputPath = "/output/trivy.json"
		result.arguments = []string{
			"filesystem", "--cache-dir", "/opt/ai-security-scanner/trivy-cache",
			"--skip-db-update", "--offline-scan", "--scanners", "vuln",
			"--format", "json", "--output", result.outputPath, "/workspace",
		}
		result.environment = append(result.environment, "TRIVY_DISABLE_VEX_NOTICE=true")
	case "grype":
		result.program = "/usr/local/bin/grype"
		result.outputPath = "/output/grype.json"
		result.arguments = []string{"dir:/workspace", "--output", "json", "--file", result.outputPath}
		result.environment = append(result.environment,
			"GRYPE_CHECK_FOR_APP_UPDATE=false",
			"GRYPE_DB_AUTO_UPDATE=false",
			"GRYPE_DB_CACHE_DIR=/opt/ai-security-scanner/grype-db",
			"GRYPE_DB_REQUIRE_UPDATE_CHECK=false",
			"GRYPE_DB_VALIDATE_AGE=false",
			"GRYPE_DB_VALIDATE_BY_HASH_ON_START=false",
		)
	case "kubescape":
		result.program = "/usr/local/bin/kubescape"
		result.outputPath = "/output/kubescape.json"
		result.arguments = []string{
			"scan", "framework", "nsa", "/workspace",
			"--use-from", "/opt/ai-security-scanner/kubescape-artifacts/nsa.json",
			"--controls-config", "/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json",
			"--exceptions", "/opt/ai-security-scanner/kubescape-artifacts/exceptions.json",
			"--keep-local", "--submit=false", "--host-scan=false",
			"--omit-raw-resources", "--format", "json", "--format-version", "v2",
			"--scan-timeout", "45m", "--control-timeout", "2m", "--output", result.outputPath,
		}
		result.environment = append(result.environment,
			"KS_SUBMIT=false", "OTEL_SDK_DISABLED=true")
	case "kube-bench":
		result.program = "/usr/local/bin/kube-bench"
		result.outputPath = "/output/kube-bench.json"
		result.arguments = []string{
			"run", "--benchmark", "ai-security-scanner-snapshot", "--targets", "node",
			"--config-dir", "/opt/ai-security-scanner/kube-bench/cfg",
			"--config", "/opt/ai-security-scanner/kube-bench/cfg/config.yaml",
			"--json", "--outputfile", result.outputPath, "--noremediations",
			"--exit-code", "0",
		}
	default:
		return invocation{}, errors.New("engine identifier is not allowlisted")
	}
	return result, nil
}

func verifyEngineInputs(engineID string, workspace string) error {
	switch engineID {
	case "semgrep":
		return verifyFile("/opt/ai-security-scanner/semgrep/rules.yml", semgrepRulesSHA256, 1024*1024)
	case "trivy":
		if err := verifyFile("/opt/ai-security-scanner/trivy-cache/db/trivy.db", trivyDBSHA256, maxImmutableBytes); err != nil {
			return err
		}
		return verifyFile("/opt/ai-security-scanner/trivy-cache/db/metadata.json", trivyMetadataSHA256, 64*1024)
	case "grype":
		return verifyFile("/opt/ai-security-scanner/grype-db/6/vulnerability.db", grypeDBSHA256, maxImmutableBytes)
	case "kubescape":
		for path, digest := range map[string]string{
			"/opt/ai-security-scanner/kubescape-artifacts/nsa.json":             kubescapeNSASHA256,
			"/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json": kubescapeControlsSHA256,
			"/opt/ai-security-scanner/kubescape-artifacts/exceptions.json":      kubescapeExceptionsSHA256,
		} {
			if err := verifyFile(path, digest, 4*1024*1024); err != nil {
				return err
			}
		}
	case "kube-bench":
		return validateNodeSnapshot(filepath.Join(workspace, "node-snapshot"))
	}
	return nil
}

func verifyFile(path string, expected string, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("required immutable input %s is unavailable: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes {
		return fmt.Errorf("required immutable input %s is not a bounded regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open immutable input %s: %w", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, maxBytes+1)); err != nil {
		return fmt.Errorf("hash immutable input %s: %w", path, err)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != expected {
		return fmt.Errorf("immutable input %s does not match its release digest", path)
	}
	return nil
}

func validateNodeSnapshot(root string) error {
	if err := validateDirectory(root, "node snapshot"); err != nil {
		return err
	}
	manifestPath := filepath.Join(root, "profile.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() < 2 || manifestInfo.Size() > 256*1024 {
		return errors.New("node snapshot requires a bounded regular profile.json")
	}
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read node snapshot profile: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var profile nodeSnapshot
	if err := decoder.Decode(&profile); err != nil {
		return fmt.Errorf("parse node snapshot profile: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("parse node snapshot profile: %w", err)
	}
	if profile.SchemaVersion != "1.0.0" || profile.Profile != "cis-kubernetes-node-config" || profile.CapturedAt.IsZero() {
		return errors.New("node snapshot profile identity is invalid")
	}
	if len(profile.Files) < 1 || len(profile.Files) > maxSnapshotFiles {
		return errors.New("node snapshot file inventory is empty or exceeds its bound")
	}
	allowed := map[string]bool{
		"kubelet-config.yaml": true,
		"kubelet.service":     true,
		"kubelet.conf":        true,
		"kube-proxy.yaml":     true,
		"ca.crt":              true,
	}
	seen := map[string]bool{}
	for _, file := range profile.Files {
		if !allowed[file.Path] || seen[file.Path] || !validSHA256(file.SHA256) {
			return fmt.Errorf("node snapshot file inventory contains an invalid entry %q", file.Path)
		}
		seen[file.Path] = true
		if err := verifyFile(filepath.Join(root, file.Path), strings.TrimPrefix(file.SHA256, "sha256:"), maxSnapshotBytes); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("enumerate node snapshot: %w", err)
	}
	if len(entries) != len(profile.Files)+1 {
		return errors.New("node snapshot contains files outside its immutable inventory")
	}
	return nil
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func execute(planned invocation) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, planned.timeout)
	defer cancel()
	command := exec.CommandContext(ctx, planned.program, planned.arguments...)
	command.Env = append([]string(nil), planned.environment...)
	command.Dir = workspaceMountPath
	if runtime.GOOS != "windows" {
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		command.Cancel = func() error {
			if command.Process == nil {
				return nil
			}
			return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
	}
	command.WaitDelay = 5 * time.Second
	logs := &boundedWriter{limit: maxLogBytes}
	command.Stderr = logs
	if planned.stdoutIsOutput {
		output, err := os.OpenFile(planned.outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create evidence file: %w", err)
		}
		command.Stdout = output
		err = command.Run()
		closeErr := output.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return commandError(ctx, err, logs)
		}
	} else {
		command.Stdout = logs
		if err := command.Run(); err != nil {
			return commandError(ctx, err, logs)
		}
	}
	if logs.overflow {
		return errors.New("engine diagnostic output exceeded its bounded capture")
	}
	return nil
}

func commandError(ctx context.Context, err error, logs *boundedWriter) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("engine exceeded its fixed runtime timeout")
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.New("engine execution was cancelled")
	}
	message := strings.TrimSpace(logs.buffer.String())
	if len(message) > 2048 {
		message = message[len(message)-2048:]
	}
	if message == "" {
		return fmt.Errorf("engine failed: %w", err)
	}
	return fmt.Errorf("engine failed: %w (%s)", err, message)
}

func validateEvidence(path string, jsonLines bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect evidence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxEvidenceBytes {
		return errors.New("engine evidence is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence: %w", err)
	}
	defer file.Close()
	if jsonLines {
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			var value map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &value); err != nil || value == nil {
				return errors.New("engine evidence contains an invalid JSON object line")
			}
		}
		return scanner.Err()
	}
	if info.Size() < 2 {
		return errors.New("engine JSON evidence is empty")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxEvidenceBytes+1))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("parse engine JSON evidence: %w", err)
	}
	if value == nil {
		return errors.New("engine JSON evidence is null")
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// These release constants are verified before any scanner starts. They are
// updated together with the corresponding Dockerfile and packaging plan.
const (
	semgrepRulesSHA256        = "2081a62359682db1ddd15eda7eed1f3931975870cef8f8dab7120ba86fe2e5f3"
	trivyDBSHA256             = "e58db9fad4ce26f9ad77f4116f7a3b52527eb3a75718484903d930d110dee431"
	trivyMetadataSHA256       = "b253a6f5e90d91bf0e0e4b6f07a6f26cb9169155d0af68309728d9d853ded143"
	grypeDBSHA256             = "db6f590412955f6b58cec12bfa4b712b2626eef9a030bffd8f32b9ebce074ff8"
	kubescapeNSASHA256        = "7f7d7bbc6908b9872fd71751dc8d5dd5f543cdd6a684a24d1fb15b686e8344db"
	kubescapeControlsSHA256   = "df4e2431e8f560961ce56aa06e022caf9b2f82f98752de78df1cd0706b42cf3a"
	kubescapeExceptionsSHA256 = "bf44e01e6b212c8e8c0ca0686d1bd84488e3f9ce5375cd36511c8faef3a44e7b"
)

// Keep deterministic ordering available to tests without exposing dynamic
// scanner arguments in production.
func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

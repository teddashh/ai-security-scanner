// Managed Agentic Radar launcher: one offline native static graph export.
// Framework parsing remains upstream; the launcher owns invocation and input boundaries.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	workspaceMountPath             = "/workspace"
	outputMountPath                = "/output"
	scopeDocumentPath              = "/run/ai-security-scanner/scope.json"
	reportPath                     = "/output/agentic-radar.json"
	engineID                       = "agentic-radar"
	frameworkNamespace             = "ai-security-scanner:agentic-radar-framework"
	workspaceSHA256Namespace       = "ai-security-scanner:workspace-snapshot-sha256"
	maxScopeBytes            int64 = 1024 * 1024
	maxEvidenceBytes         int64 = 32 * 1024 * 1024
	linuxStatfsReadOnly            = 1
)

type boundedWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := writer.limit - writer.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = writer.buffer.Write(value)
	}
	return original, nil
}

type scopeDocument struct {
	SchemaVersion string       `json:"schema_version"`
	EngineID      string       `json:"engine_id"`
	GeneratedAt   string       `json:"generated_at"`
	Assets        []scopeAsset `json:"assets"`
}

type scopeAsset struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Provider    *string           `json:"provider"`
	Region      *string           `json:"region"`
	Identifiers []scopeIdentifier `json:"identifiers"`
	Grants      []scopeGrant      `json:"grants"`
}

type scopeIdentifier struct {
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

type scopeGrant struct {
	ID                     string          `json:"id"`
	Permission             string          `json:"permission"`
	ConfirmedBy            string          `json:"confirmed_by"`
	ConfirmedAt            string          `json:"confirmed_at"`
	ExpiresAt              *string         `json:"expires_at"`
	AuthorizationReference *string         `json:"authorization_reference"`
	ExternalScope          json.RawMessage `json:"external_scope"`
}

type terminalEnvelope struct {
	SchemaVersion  string            `json:"schema_version"`
	ScannerVersion string            `json:"scanner_version"`
	Framework      string            `json:"framework"`
	Status         string            `json:"status"`
	Complete       *bool             `json:"complete"`
	Warnings       []json.RawMessage `json:"warnings"`
	Graph          struct {
		Nodes  []json.RawMessage `json:"nodes"`
		Edges  []json.RawMessage `json:"edges"`
		Agents []json.RawMessage `json:"agents"`
		Tools  []json.RawMessage `json:"tools"`
	} `json:"graph"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "managed Agentic Radar launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-agentic-radar-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestedEngine := flags.String("engine", "", "fixed engine identity")
	workspace := flags.String("workspace", "", "immutable repository snapshot")
	output := flags.String("output", "", "runtime-owned evidence directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if *requestedEngine != engineID || *workspace != workspaceMountPath || *output != outputMountPath {
		return errors.New("engine, workspace and output must use the runtime-owned contract")
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
	framework, err := readSelection(scopeDocumentPath)
	if err != nil {
		return err
	}
	if err := ensureAbsent(reportPath); err != nil {
		return err
	}
	if err := os.MkdirAll("/tmp/ai-security-scanner-home", 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/local/bin/python3", fixedArguments(framework)...)
	command.Dir = "/tmp/ai-security-scanner-home"
	command.Env = []string{
		"HOME=/tmp/ai-security-scanner-home", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		"NO_COLOR=1", "PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1",
		"PYTHONHASHSEED=0", "PYTHONNOUSERSITE=1", "PYTHONUNBUFFERED=1",
		"PYTHON_DOTENV_DISABLED=1", "TMPDIR=/tmp", "XDG_CACHE_HOME=/tmp/ai-security-scanner-cache",
	}
	var diagnostic boundedWriter
	diagnostic.limit = 1024 * 1024
	command.Stdout = &diagnostic
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		_ = os.Remove(reportPath)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("Agentic Radar exceeded its fixed ten-minute runtime limit")
		}
		return fmt.Errorf("Agentic Radar workflow inventory failed: %w", err)
	}
	if err := validateTerminalEvidence(reportPath, framework); err != nil {
		_ = os.Remove(reportPath)
		return err
	}
	return os.Chmod(reportPath, 0o600)
}

func supportedFramework(value string) bool {
	switch value {
	case "langgraph", "crewai", "n8n", "openai-agents", "autogen":
		return true
	}
	return false
}

func fixedArguments(framework string) []string {
	return []string{"-I", "-B", "-m", "agentic_radar", "scan", framework,
		"--input-dir", workspaceMountPath, "--export-graph-json", "--output-file", reportPath}
}

func validateTerminalEvidence(path string, framework string) error {
	file, err := openBoundedRegularFile(path, maxEvidenceBytes, "Agentic Radar evidence")
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxEvidenceBytes+1))
	var envelope terminalEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("parse Agentic Radar evidence: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("Agentic Radar evidence contains trailing JSON")
	}
	if envelope.SchemaVersion != "1" || envelope.ScannerVersion != "0.14.1" || !supportedFramework(framework) || envelope.Framework != framework {
		return errors.New("Agentic Radar evidence does not match the pinned version and selected framework")
	}
	if envelope.Status != "workflow_found" && envelope.Status != "no_supported_workflow" {
		return errors.New("Agentic Radar evidence has an unsupported terminal status")
	}
	if envelope.Complete == nil || envelope.Warnings == nil || envelope.Graph.Nodes == nil || envelope.Graph.Edges == nil || envelope.Graph.Agents == nil || envelope.Graph.Tools == nil {
		return errors.New("Agentic Radar evidence omitted a terminal collection")
	}
	if *envelope.Complete != (len(envelope.Warnings) == 0) {
		return errors.New("Agentic Radar completeness disagrees with its warnings")
	}
	if (envelope.Status == "workflow_found") != (len(envelope.Graph.Nodes) > 2) {
		return errors.New("Agentic Radar terminal status disagrees with the native graph")
	}
	return nil
}

func readSelection(path string) (string, error) {
	file, err := openBoundedRegularFile(path, maxScopeBytes, "scope document")
	if err != nil {
		return "", err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxScopeBytes+1))
	decoder.DisallowUnknownFields()
	var document scopeDocument
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("parse scope document: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", errors.New("scope document contains trailing JSON")
	}
	if document.SchemaVersion != "1" || document.EngineID != engineID || len(document.Assets) != 1 {
		return "", errors.New("scope document does not name one Agentic Radar repository asset")
	}
	asset := document.Assets[0]
	if asset.ID == "" || asset.Kind != "repository" || len(asset.Grants) != 1 || asset.Grants[0].Permission != "local_artifact_read" {
		return "", errors.New("scope document lacks one exact local-artifact grant")
	}
	if asset.Grants[0].ID == "" || strings.TrimSpace(asset.Grants[0].ConfirmedBy) == "" || asset.Grants[0].ConfirmedAt == "" {
		return "", errors.New("scope document local-artifact grant is incomplete")
	}
	values := make(map[string][]string)
	for _, identifier := range asset.Identifiers {
		values[identifier.Namespace] = append(values[identifier.Namespace], identifier.Value)
	}
	if len(values[workspaceSHA256Namespace]) != 1 || !validSHA256(values[workspaceSHA256Namespace][0]) {
		return "", errors.New("scope document lacks one immutable workspace digest")
	}
	if len(values[frameworkNamespace]) != 1 || !supportedFramework(values[frameworkNamespace][0]) {
		return "", errors.New("scope document lacks one supported framework selection")
	}
	grant := asset.Grants[0]
	confirmed, err := time.Parse(time.RFC3339, grant.ConfirmedAt)
	if err != nil || confirmed.After(time.Now().Add(time.Minute)) || len(grant.ExternalScope) != 0 && string(grant.ExternalScope) != "null" {
		return "", errors.New("local-artifact grant has invalid time or external scope")
	}
	if grant.ExpiresAt != nil {
		expires, err := time.Parse(time.RFC3339, *grant.ExpiresAt)
		if err != nil || !expires.After(time.Now()) {
			return "", errors.New("local-artifact grant expired")
		}
	}
	return values[frameworkNamespace][0], nil
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

func ensureAbsent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect evidence path: %w", err)
	}
	return fmt.Errorf("evidence path already exists (%s, mode %s)", path, info.Mode())
}

func openBoundedRegularFile(path string, maxBytes int64, label string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is not a bounded regular file", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	return file, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

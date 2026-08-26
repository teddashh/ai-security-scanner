// ai-security-scanner-gitleaks-launcher is a non-shell capability boundary for
// a current-project secret scan. It never forwards target-controlled options
// and it refuses to persist a report whose Secret fields are not fully redacted.
package main

import (
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
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

const (
	workspaceMountPath  = "/workspace"
	outputMountPath     = "/output"
	reportPath          = "/output/gitleaks.json"
	configPath          = "/opt/ai-security-scanner/gitleaks/gitleaks.toml"
	configSHA256        = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
	maxConfigBytes      = 2 * 1024 * 1024
	maxEvidenceBytes    = 512 * 1024 * 1024
	linuxStatfsReadOnly = 1
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

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "managed Gitleaks launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-gitleaks-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	workspace := flags.String("workspace", "", "read-only current-project snapshot")
	output := flags.String("output", "", "runtime-owned evidence directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
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
	if err := verifyFile(configPath, configSHA256, maxConfigBytes); err != nil {
		return err
	}
	if err := ensureAbsent(reportPath); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/local/bin/gitleaks", fixedArguments()...)
	command.Dir = workspaceMountPath
	command.Env = []string{
		"HOME=/tmp/ai-security-scanner-home",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"NO_COLOR=1",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME=/tmp/ai-security-scanner-cache",
	}
	var diagnostic boundedWriter
	diagnostic.limit = 8 * 1024 * 1024
	command.Stdout = &diagnostic
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		_ = os.Remove(reportPath)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("Gitleaks exceeded its fixed one-hour runtime limit")
		}
		return fmt.Errorf("Gitleaks execution failed: %w", err)
	}
	if err := validateRedactedEvidence(reportPath); err != nil {
		_ = os.Remove(reportPath)
		return err
	}
	return os.Chmod(reportPath, 0o600)
}

func fixedArguments() []string {
	return []string{
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

func verifyFile(path string, expected string, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect immutable input %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes {
		return fmt.Errorf("immutable input %s is not a bounded regular file", path)
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
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return fmt.Errorf("immutable input %s does not match its release digest", path)
	}
	return nil
}

func validateRedactedEvidence(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Gitleaks evidence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > maxEvidenceBytes {
		return errors.New("Gitleaks evidence is not a bounded regular JSON file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Gitleaks evidence: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxEvidenceBytes+1))
	var findings []map[string]json.RawMessage
	if err := decoder.Decode(&findings); err != nil {
		return fmt.Errorf("parse Gitleaks evidence: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("Gitleaks evidence contains trailing JSON")
	}
	for _, finding := range findings {
		rawSecret, present := finding["Secret"]
		if !present {
			return errors.New("Gitleaks evidence omitted its redaction sentinel")
		}
		var secret string
		if err := json.Unmarshal(rawSecret, &secret); err != nil || secret != "REDACTED" {
			return errors.New("Gitleaks evidence contains an unredacted secret field")
		}
	}
	return nil
}

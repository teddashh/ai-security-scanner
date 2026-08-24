// ai-security-scanner-cloud-launcher is the non-shell capability boundary used
// by the managed cloud engine images. It accepts only the immutable scope and
// short-lived credential documents mounted by the desktop runtime, selects one
// fixed provider profile from the exact credential-key set, and starts only a
// project-owned static command plan.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	credentialPath    = "/run/ai-security-scanner/credentials.json"
	maxCredentialSize = 256 * 1024
	maxScopeSize      = 4 * 1024 * 1024
	maxOutputFileSize = 512 * 1024 * 1024
)

var safeEnvironmentKeys = []string{
	"ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy", "AI_SECURITY_SCANNER_PROXY", "LANG", "LC_ALL", "PATH",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
}

type scopeDocument struct {
	SchemaVersion string       `json:"schema_version"`
	EngineID      string       `json:"engine_id"`
	GeneratedAt   string       `json:"generated_at"`
	Assets        []scopeAsset `json:"assets"`
}

type scopeAsset struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Kind        string       `json:"kind"`
	Provider    *string      `json:"provider"`
	Region      *string      `json:"region"`
	Identifiers []identifier `json:"identifiers"`
	Grants      []scopeGrant `json:"grants"`
}

type identifier struct {
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

type credentialEnvelope struct {
	SchemaVersion string            `json:"schema_version"`
	Credentials   []credentialEntry `json:"credentials"`
}

type credentialEntry struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
	Source    string    `json:"source"`
}

type provider string

const (
	providerAWS   provider = "aws"
	providerAzure provider = "azure"
	providerGCP   provider = "gcp"
)

type invocation struct {
	Program string
	Args    []string
	Env     []string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cloud engine launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-cloud-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engineID := flags.String("engine", "", "fixed engine identifier")
	scopePath := flags.String("scope", "", "immutable scope document")
	outputPath := flags.String("output", "", "evidence output directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if !supportedEngine(*engineID) {
		return errors.New("engine identifier is not allowlisted")
	}
	if *scopePath != "/run/ai-security-scanner/scope.json" || *outputPath != "/output" {
		return errors.New("scope and output paths must use the runtime-owned mounts")
	}
	if err := validateOutputDirectory(*outputPath); err != nil {
		return err
	}
	scope, err := loadScope(*scopePath, *engineID)
	if err != nil {
		return err
	}
	credentials, selectedProvider, err := loadCredentials(credentialPath)
	if err != nil {
		return err
	}
	if err := validateProviderForEngine(*engineID, selectedProvider, scope); err != nil {
		return err
	}
	if err := validateScopePermissions(scope, *engineID); err != nil {
		return err
	}

	temporaryRoot, err := os.MkdirTemp("/tmp", "ai-security-scanner-cloud-")
	if err != nil {
		return fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		return fmt.Errorf("restrict private temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)

	environment := childEnvironment(credentials, selectedProvider, temporaryRoot)
	switch *engineID {
	case "cloudsplaining":
		return runCloudsplaining(environment, temporaryRoot, *outputPath)
	case "prowler":
		return runCommand(invocation{
			Program: "/home/prowler/.venv/bin/prowler",
			Args: []string{
				"aws", "--service", "iam", "--region", "us-east-1",
				"--output-formats", "json-ocsf", "--output-filename", "prowler",
				"--output-directory", *outputPath, "--ignore-exit-code-3",
				"--no-banner", "--no-color", "--skip-sh-update",
			},
			Env: environment,
		})
	case "scoutsuite":
		return runScoutSuite(environment, temporaryRoot, *outputPath)
	case "cloudquery":
		return runCloudQuery(environment, temporaryRoot)
	case "steampipe":
		return runSteampipe(environment, temporaryRoot, *outputPath)
	default:
		return errors.New("unreachable engine dispatch")
	}
}

func supportedEngine(engineID string) bool {
	switch engineID {
	case "cloudquery", "prowler", "scoutsuite", "cloudsplaining", "steampipe":
		return true
	default:
		return false
	}
}

func loadScope(path, expectedEngine string) (*scopeDocument, error) {
	bytes, err := readBoundedRegularFile(path, maxScopeSize)
	if err != nil {
		return nil, fmt.Errorf("read immutable scope: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(bytes)))
	decoder.DisallowUnknownFields()
	var scope scopeDocument
	if err := decoder.Decode(&scope); err != nil {
		return nil, errors.New("scope document is malformed")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errors.New("scope document has trailing data")
	}
	if scope.SchemaVersion != "1" || scope.EngineID != expectedEngine || len(scope.Assets) == 0 || len(scope.Assets) > 4096 {
		return nil, errors.New("scope document version, engine, or asset count is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, scope.GeneratedAt); err != nil {
		return nil, errors.New("scope document timestamp is invalid")
	}
	seen := make(map[string]struct{}, len(scope.Assets))
	for _, asset := range scope.Assets {
		if !safeText(asset.ID, 256) || !safeText(asset.Name, 4096) || !safeText(asset.Kind, 128) {
			return nil, errors.New("scope contains an invalid asset")
		}
		if asset.Provider == nil || *asset.Provider != "aws" {
			return nil, errors.New("released cloud engine scope must identify the AWS provider")
		}
		if asset.Region != nil && !safeText(*asset.Region, 128) {
			return nil, errors.New("scope contains an invalid provider region")
		}
		if _, exists := seen[asset.ID]; exists {
			return nil, errors.New("scope contains a duplicate asset")
		}
		seen[asset.ID] = struct{}{}
		if len(asset.Identifiers) > 128 || len(asset.Grants) == 0 || len(asset.Grants) > 16 {
			return nil, errors.New("scope asset identifiers or grants are outside bounds")
		}
		for _, identifier := range asset.Identifiers {
			if !safeText(identifier.Namespace, 256) || !safeText(identifier.Value, 4096) {
				return nil, errors.New("scope contains an invalid identifier")
			}
		}
	}
	return &scope, nil
}

func validateScopePermissions(scope *scopeDocument, engineID string) error {
	required := map[string]bool{"inventory_read": true}
	if engineID != "cloudquery" && engineID != "steampipe" {
		required["configuration_read"] = true
	}
	for _, asset := range scope.Assets {
		granted := make(map[string]bool)
		for _, grant := range asset.Grants {
			if !safeText(grant.ID, 256) || !safeText(grant.ConfirmedBy, 1024) {
				return errors.New("scope contains an invalid grant")
			}
			if len(grant.ExternalScope) != 0 && !bytes.Equal(bytes.TrimSpace(grant.ExternalScope), []byte("null")) {
				return errors.New("passive cloud engines do not accept an active external scope")
			}
			if _, err := time.Parse(time.RFC3339Nano, grant.ConfirmedAt); err != nil {
				return errors.New("scope grant timestamp is invalid")
			}
			if grant.ExpiresAt != nil {
				expiry, err := time.Parse(time.RFC3339Nano, *grant.ExpiresAt)
				if err != nil || !expiry.After(time.Now().UTC()) {
					return errors.New("scope grant is expired or malformed")
				}
			}
			granted[grant.Permission] = true
		}
		for permission := range required {
			if !granted[permission] {
				return fmt.Errorf("scope asset lacks %s", permission)
			}
		}
	}
	return nil
}

func loadCredentials(path string) (map[string]string, provider, error) {
	bytes, err := readBoundedRegularFile(path, maxCredentialSize)
	if err != nil {
		return nil, "", fmt.Errorf("read protected credential channel: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(bytes)))
	decoder.DisallowUnknownFields()
	var envelope credentialEnvelope
	if err := decoder.Decode(&envelope); err != nil || requireJSONEOF(decoder) != nil {
		return nil, "", errors.New("credential channel is malformed")
	}
	if envelope.SchemaVersion != "1.0.0" || len(envelope.Credentials) == 0 || len(envelope.Credentials) > 3 {
		return nil, "", errors.New("credential channel version or entry count is invalid")
	}
	values := make(map[string]string, len(envelope.Credentials))
	for _, credential := range envelope.Credentials {
		if !allowedCredentialKey(credential.Key) || credential.Value == "" || len(credential.Value) > 64*1024 {
			return nil, "", errors.New("credential channel contains an unauthorized entry")
		}
		if credential.Source != "ephemeral_scan_role" && credential.Source != "external_read_only_grant" {
			return nil, "", errors.New("credential source is not a scanner-only source")
		}
		if !credential.ExpiresAt.After(time.Now().UTC()) {
			return nil, "", errors.New("credential channel contains an expired entry")
		}
		if _, exists := values[credential.Key]; exists {
			return nil, "", errors.New("credential channel contains a duplicate key")
		}
		values[credential.Key] = credential.Value
	}
	selected, err := providerFromCredentialKeys(values)
	if err != nil {
		return nil, "", err
	}
	return values, selected, nil
}

func providerFromCredentialKeys(values map[string]string) (provider, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	signature := strings.Join(keys, ",")
	switch signature {
	case "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN":
		return providerAWS, nil
	case "AZURE_ACCESS_TOKEN":
		return providerAzure, nil
	case "GOOGLE_OAUTH_ACCESS_TOKEN":
		return providerGCP, nil
	default:
		return "", errors.New("credential keys do not match one complete provider profile")
	}
}

func validateProviderForEngine(engineID string, selected provider, scope *scopeDocument) error {
	// This release intentionally exposes only the AWS IAM subsets. Azure and
	// GCP SDKs used by these upstreams do not consume the token-only profiles
	// offered by ScannerCredentialSet without writing credential files or
	// broadening the provider endpoint set.
	if selected != providerAWS {
		return fmt.Errorf("engine %s has no released %s token profile", engineID, selected)
	}
	for _, asset := range scope.Assets {
		if asset.Provider == nil || *asset.Provider != string(selected) {
			return errors.New("credential provider does not match immutable asset scope")
		}
	}
	return nil
}

func childEnvironment(credentials map[string]string, selected provider, temporaryRoot string) []string {
	values := make(map[string]string)
	for _, key := range safeEnvironmentKeys {
		if value, exists := os.LookupEnv(key); exists {
			values[key] = value
		}
	}
	for key, value := range credentials {
		values[key] = value
	}
	values["HOME"] = temporaryRoot
	values["USER"] = "scanner"
	values["XDG_CACHE_HOME"] = filepath.Join(temporaryRoot, "cache")
	values["AWS_EC2_METADATA_DISABLED"] = "true"
	values["AWS_DEFAULT_REGION"] = "us-east-1"
	values["AWS_REGION"] = "us-east-1"
	values["AWS_MAX_ATTEMPTS"] = "2"
	values["AWS_RETRY_MODE"] = "standard"
	values["AWS_STS_REGIONAL_ENDPOINTS"] = "regional"
	values["AWS_SDK_LOAD_CONFIG"] = "false"
	values["CLOUDQUERY_TELEMETRY_LEVEL"] = "none"
	values["STEAMPIPE_INSTALL_DIR"] = filepath.Join(temporaryRoot, "steampipe")
	values["STEAMPIPE_TELEMETRY"] = "none"
	values["STEAMPIPE_UPDATE_CHECK"] = "false"
	values["STEAMPIPE_CACHE"] = "false"
	values["STEAMPIPE_MAX_PARALLEL"] = "4"
	values["STEAMPIPE_MEMORY_MAX_MB"] = "768"
	_ = selected
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment
}

func runCloudsplaining(environment []string, temporaryRoot, output string) error {
	downloadDirectory := filepath.Join(temporaryRoot, "authorization")
	if err := os.Mkdir(downloadDirectory, 0o700); err != nil {
		return fmt.Errorf("create authorization directory: %w", err)
	}
	// Cloudsplaining 0.9.1 historically returns one after a successful
	// download, so success is established by the bounded regular output file.
	download := invocation{
		Program: "/opt/cloudsplaining/bin/cloudsplaining",
		Args:    []string{"download", "--output", downloadDirectory},
		Env:     environment,
	}
	exitCode, runErr := runCommandStatus(download)
	input := filepath.Join(downloadDirectory, "default.json")
	if runErr != nil || (exitCode != 0 && exitCode != 1) {
		return errors.New("Cloudsplaining authorization download failed")
	}
	if _, err := readBoundedRegularFile(input, maxOutputFileSize); err != nil {
		return errors.New("Cloudsplaining did not produce bounded authorization details")
	}
	reportDirectory := filepath.Join(temporaryRoot, "report")
	if err := os.Mkdir(reportDirectory, 0o700); err != nil {
		return fmt.Errorf("create Cloudsplaining report directory: %w", err)
	}
	if err := runCommand(invocation{
		Program: "/opt/cloudsplaining/bin/cloudsplaining",
		Args:    []string{"scan", "--input-file", input, "--output", reportDirectory, "--skip-open-report"},
		Env:     environment,
	}); err != nil {
		return err
	}
	source := filepath.Join(reportDirectory, "iam-findings-default.json")
	destination := filepath.Join(output, "cloudsplaining.json")
	if err := moveBoundedRegularFile(source, destination); err != nil {
		return fmt.Errorf("normalize Cloudsplaining findings: %w", err)
	}
	return nil
}

func runScoutSuite(environment []string, temporaryRoot, output string) error {
	reportDirectory := filepath.Join(temporaryRoot, "scoutsuite-report")
	if err := os.Mkdir(reportDirectory, 0o700); err != nil {
		return fmt.Errorf("create ScoutSuite report directory: %w", err)
	}
	if err := runCommand(invocation{
		Program: "/opt/scoutsuite/bin/scout",
		Args: []string{
			"aws", "--services", "iam", "--no-browser", "--force",
			"--report-dir", reportDirectory, "--report-name", "scoutsuite",
			"--result-format", "json", "--max-workers", "4",
		},
		Env: environment,
	}); err != nil {
		return err
	}
	source := filepath.Join(reportDirectory, "scoutsuite-results", "scoutsuite_results_scoutsuite.js")
	payload, err := readBoundedRegularFile(source, maxOutputFileSize)
	if err != nil {
		return errors.New("ScoutSuite did not produce its bounded result document")
	}
	const prefix = "scoutsuite_results ="
	trimmed := payload
	if bytes.HasPrefix(payload, []byte(prefix)) {
		trimmed = bytes.TrimSpace(bytes.TrimPrefix(payload, []byte(prefix)))
	}
	if !json.Valid(trimmed) {
		return errors.New("ScoutSuite result document is not valid JSON")
	}
	return writeExclusive(filepath.Join(output, "scoutsuite.json"), trimmed, 0o600)
}

func runCloudQuery(environment []string, temporaryRoot string) error {
	configPath := filepath.Join(temporaryRoot, "cloudquery.yml")
	if err := writeExclusive(configPath, cloudQueryConfiguration(), 0o600); err != nil {
		return fmt.Errorf("write fixed CloudQuery config: %w", err)
	}
	return runCommand(invocation{
		Program: "/app/cloudquery",
		Args: []string{
			"sync", configPath, "--cq-dir", filepath.Join(temporaryRoot, "cq"),
			"--no-log-file", "--log-console", "--telemetry-level", "none",
		},
		Env: environment,
	})
}

func cloudQueryConfiguration() []byte {
	return []byte(`kind: source
spec:
  name: aws
  path: /usr/local/libexec/cloudquery-source-aws
  registry: local
  destinations: [file]
  tables:
    - aws_iam_accounts
    - aws_iam_credential_reports
    - aws_iam_groups
    - aws_iam_password_policies
    - aws_iam_policies
    - aws_iam_roles
    - aws_iam_users
  spec:
    regions: [us-east-1]
---
kind: destination
spec:
  name: file
  path: /usr/local/libexec/cloudquery-destination-file
  registry: local
  write_mode: append
  spec:
    directory: /output
    format: json
    no_rotate: true
`)
}

func runSteampipe(environment []string, temporaryRoot, output string) (result error) {
	// The runtime deliberately mounts /tmp noexec. Keep that hardening intact:
	// Steampipe's executable PostgreSQL and plugin files use one exact hidden
	// directory in the case-owned output mount, which is removed on every exit.
	installDir := filepath.Join(output, ".ai-security-scanner-steampipe-runtime")
	if _, err := os.Lstat(installDir); !errors.Is(err, os.ErrNotExist) {
		return errors.New("transient Steampipe state already exists")
	}
	if err := copyTree("/opt/ai-security-scanner/steampipe-install", installDir); err != nil {
		return fmt.Errorf("prepare ephemeral Steampipe state: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(installDir); err != nil {
			result = errors.Join(result, errors.New("remove transient Steampipe state"))
		}
	}()
	environment = replaceEnvironmentValue(environment, "STEAMPIPE_INSTALL_DIR", installDir)
	configDirectory := filepath.Join(installDir, "config")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		return fmt.Errorf("create Steampipe config directory: %w", err)
	}
	config := `connection "aws" {
  plugin = "local/aws"
  regions = ["us-east-1"]
}
options "database" {
  cache = false
}
`
	if err := writeExclusive(filepath.Join(configDirectory, "aws.spc"), []byte(config), 0o600); err != nil {
		return fmt.Errorf("write fixed Steampipe config: %w", err)
	}
	queryPath := filepath.Join(temporaryRoot, "iam.sql")
	query := `select
  'steampipe:aws_iam_user_mfa' as control_id,
  case when mfa_enabled then 'pass' else 'fail' end as status,
  'IAM user should have a registered MFA device' as title,
  'high' as severity,
  arn as resource,
  account_id as asset_id
from aws_iam_user;
`
	if err := writeExclusive(queryPath, []byte(query), 0o600); err != nil {
		return fmt.Errorf("write fixed Steampipe query: %w", err)
	}
	return runCommandToFile(invocation{
		Program: "/usr/local/bin/steampipe",
		Args: []string{
			"query", "--output", "json", queryPath,
		},
		Env: environment,
	}, filepath.Join(output, "steampipe.json"))
}

func replaceEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	replaced := false
	result := append([]string(nil), environment...)
	for index, entry := range result {
		if strings.HasPrefix(entry, prefix) {
			result[index] = prefix + value
			replaced = true
		}
	}
	if !replaced {
		result = append(result, prefix+value)
		sort.Strings(result)
	}
	return result
}

func runCommand(invocation invocation) error {
	exitCode, err := runCommandStatusWithOutput(invocation, os.Stdout)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("engine process exited with status %d", exitCode)
	}
	return nil
}

func runCommandStatus(invocation invocation) (int, error) {
	return runCommandStatusWithOutput(invocation, os.Stdout)
}

func runCommandStatusWithOutput(invocation invocation, stdout io.Writer) (int, error) {
	if !strings.HasPrefix(invocation.Program, "/") || len(invocation.Args) > 128 {
		return -1, errors.New("engine invocation is not static and absolute")
	}
	command := exec.Command(invocation.Program, invocation.Args...)
	command.Env = invocation.Env
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode(), nil
	}
	return -1, errors.New("engine process could not start")
}

type boundedOutputWriter struct {
	file      *os.File
	remaining int64
	exceeded  bool
}

func (writer *boundedOutputWriter) Write(content []byte) (int, error) {
	if int64(len(content)) > writer.remaining {
		writer.exceeded = true
		return 0, errors.New("engine output exceeds its bounded evidence file")
	}
	written, err := writer.file.Write(content)
	writer.remaining -= int64(written)
	return written, err
}

func runCommandToFile(invocation invocation, destination string) error {
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("normalized output already exists")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create normalized output")
	}
	writer := &boundedOutputWriter{file: file, remaining: maxOutputFileSize}
	exitCode, runErr := runCommandStatusWithOutput(invocation, writer)
	closeErr := file.Close()
	if writer.exceeded || runErr != nil || exitCode != 0 || closeErr != nil {
		if removeErr := os.Remove(destination); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.New("remove incomplete normalized output")
		}
		switch {
		case writer.exceeded:
			return errors.New("engine output exceeds its bounded evidence file")
		case runErr != nil:
			return runErr
		case exitCode != 0:
			return fmt.Errorf("engine process exited with status %d", exitCode)
		default:
			return errors.New("close normalized output")
		}
	}
	return nil
}

func validateOutputDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output mount must be a real directory")
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func moveBoundedRegularFile(source, destination string) error {
	if _, err := readBoundedRegularFile(source, maxOutputFileSize); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("normalized output already exists")
	}
	return os.Rename(source, destination)
}

func writeExclusive(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func safeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' || character < 0x20 {
			return false
		}
	}
	return true
}

func allowedCredentialKey(key string) bool {
	switch key {
	case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN":
		return true
	default:
		return false
	}
}

func copyTree(source, destination string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.IsDir() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed state template is unavailable")
	}
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("managed state path escaped its template")
		}
		target := filepath.Join(destination, relative)
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("managed state template contains a symlink")
		}
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() || info.Size() > maxOutputFileSize {
			return errors.New("managed state template contains an unsupported file")
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeExclusive(target, bytes, info.Mode().Perm()&0o700)
	})
}

// Keep syscall linked in the static launcher so Docker stop signals are
// represented consistently by Go's exec package on Linux.
var _ = syscall.SIGTERM

// ai-security-scanner-m365-launcher is the non-shell capability boundary for
// the managed ScubaGear and Maester images. It accepts only the runtime-owned
// scope and credential mounts, proves that one Microsoft 365 tenant has the
// required read-only grants, and starts one image-owned PowerShell script.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	credentialPath    = "/run/ai-security-scanner/credentials.json"
	maximumCredential = 256 * 1024
	maximumScope      = 4 * 1024 * 1024
	maximumToken      = 128 * 1024
	maximumTokenLife  = 65 * time.Minute
	powershell        = "/opt/microsoft/powershell/7/pwsh"
)

var safeProxyKeys = []string{
	"AI_SECURITY_SCANNER_PROXY",
	"ALL_PROXY", "all_proxy",
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
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

type invocation struct {
	Program string
	Args    []string
	Env     []string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "microsoft 365 engine launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-m365-launcher", flag.ContinueOnError)
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
	if _, err := loadScope(*scopePath, *engineID, time.Now().UTC()); err != nil {
		return err
	}
	if err := validateCredentials(credentialPath, time.Now().UTC()); err != nil {
		return err
	}
	plan, err := fixedInvocation(*engineID, os.Environ())
	if err != nil {
		return err
	}
	return syscall.Exec(plan.Program, plan.Args, plan.Env)
}

func supportedEngine(engineID string) bool {
	return engineID == "scubagear" || engineID == "maester"
}

func fixedInvocation(engineID string, parentEnvironment []string) (invocation, error) {
	var script string
	switch engineID {
	case "scubagear":
		script = "/opt/ai-security-scanner/run-scubagear.ps1"
	case "maester":
		script = "/opt/ai-security-scanner/run-maester.ps1"
	default:
		return invocation{}, errors.New("engine identifier is not allowlisted")
	}
	environment, err := childEnvironment(parentEnvironment, engineID)
	if err != nil {
		return invocation{}, err
	}
	return invocation{
		Program: powershell,
		Args: []string{
			powershell,
			"-NoLogo",
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-File", script,
		},
		Env: environment,
	}, nil
}

func childEnvironment(parentEnvironment []string, engineID string) ([]string, error) {
	values := make(map[string]string)
	for _, entry := range parentEnvironment {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		for _, allowed := range safeProxyKeys {
			if key == allowed {
				if len(value) > 4096 || strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n") {
					return nil, errors.New("managed proxy environment is malformed")
				}
				values[key] = value
				break
			}
		}
	}
	static := map[string]string{
		"HOME":                        "/tmp/ai-security-scanner-home",
		"LANG":                        "C.UTF-8",
		"LC_ALL":                      "C.UTF-8",
		"PATH":                        "/opt/microsoft/powershell/7:/usr/local/bin:/usr/bin:/bin",
		"POWERSHELL_TELEMETRY_OPTOUT": "1",
		"POWERSHELL_UPDATECHECK":      "Off",
		"PSModulePath":                "/opt/ai-security-scanner/modules:/opt/microsoft/powershell/7/Modules",
		"TERM":                        "dumb",
		"XDG_CACHE_HOME":              "/tmp/ai-security-scanner-cache",
		"XDG_CONFIG_HOME":             "/tmp/ai-security-scanner-config",
		"XDG_DATA_HOME":               "/tmp/ai-security-scanner-data",
		"DOTNET_CLI_TELEMETRY_OPTOUT": "1",
		"DOTNET_NOLOGO":               "1",
		"NUGET_XMLDOC_MODE":           "skip",
	}
	if engineID == "scubagear" {
		static["SCUBAGEAR_SKIP_VERSION_CHECK"] = "1"
	}
	for key, value := range static {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func loadScope(path, expectedEngine string, now time.Time) (*scopeDocument, error) {
	payload, err := readBoundedRegularFile(path, maximumScope)
	if err != nil {
		return nil, fmt.Errorf("read immutable scope: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var scope scopeDocument
	if err := decoder.Decode(&scope); err != nil || requireJSONEOF(decoder) != nil {
		return nil, errors.New("scope document is malformed")
	}
	if scope.SchemaVersion != "1" || scope.EngineID != expectedEngine || len(scope.Assets) != 1 {
		return nil, errors.New("scope must bind the selected engine to exactly one tenant")
	}
	if _, err := time.Parse(time.RFC3339Nano, scope.GeneratedAt); err != nil {
		return nil, errors.New("scope document timestamp is invalid")
	}
	asset := scope.Assets[0]
	if !safeText(asset.ID, 256) || !safeText(asset.Name, 4096) || asset.Kind != "tenant" {
		return nil, errors.New("scope contains an invalid tenant asset")
	}
	if asset.Provider == nil || *asset.Provider != "microsoft365" || asset.Region != nil {
		return nil, errors.New("scope is not a Microsoft 365 tenant")
	}
	if len(asset.Identifiers) == 0 || len(asset.Identifiers) > 128 || len(asset.Grants) == 0 || len(asset.Grants) > 16 {
		return nil, errors.New("scope tenant identifiers or grants are outside bounds")
	}
	for _, value := range asset.Identifiers {
		if !safeText(value.Namespace, 256) || !safeText(value.Value, 4096) {
			return nil, errors.New("scope contains an invalid tenant identifier")
		}
	}
	permissions := make(map[string]bool)
	for _, grant := range asset.Grants {
		if !safeText(grant.ID, 256) || !safeText(grant.ConfirmedBy, 1024) {
			return nil, errors.New("scope contains an invalid grant")
		}
		if grant.Permission != "inventory_read" && grant.Permission != "configuration_read" {
			return nil, errors.New("Microsoft 365 engines accept only passive read grants")
		}
		if _, err := time.Parse(time.RFC3339Nano, grant.ConfirmedAt); err != nil {
			return nil, errors.New("scope grant timestamp is invalid")
		}
		if grant.ExpiresAt != nil {
			expiry, err := time.Parse(time.RFC3339Nano, *grant.ExpiresAt)
			if err != nil || !expiry.After(now) {
				return nil, errors.New("scope grant is expired or malformed")
			}
		}
		if grant.AuthorizationReference != nil && !safeText(*grant.AuthorizationReference, 4096) {
			return nil, errors.New("scope authorization reference is invalid")
		}
		if len(grant.ExternalScope) != 0 && !bytes.Equal(bytes.TrimSpace(grant.ExternalScope), []byte("null")) {
			return nil, errors.New("passive Microsoft 365 engines reject active external scope")
		}
		permissions[grant.Permission] = true
	}
	if !permissions["inventory_read"] || !permissions["configuration_read"] {
		return nil, errors.New("scope lacks required read-only inventory or configuration grant")
	}
	return &scope, nil
}

func validateCredentials(path string, now time.Time) error {
	payload, err := readBoundedRegularFile(path, maximumCredential)
	if err != nil {
		return fmt.Errorf("read protected credential channel: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope credentialEnvelope
	if err := decoder.Decode(&envelope); err != nil || requireJSONEOF(decoder) != nil {
		return errors.New("credential channel is malformed")
	}
	if envelope.SchemaVersion != "1.0.0" || len(envelope.Credentials) != 1 {
		return errors.New("credential channel must contain exactly one provider token")
	}
	credential := envelope.Credentials[0]
	if credential.Key != "MSGRAPH_ACCESS_TOKEN" || credential.Value == "" || len(credential.Value) > maximumToken {
		return errors.New("credential channel contains an unauthorized entry")
	}
	if strings.ContainsRune(credential.Value, '\x00') || strings.ContainsAny(credential.Value, "\r\n") {
		return errors.New("credential channel contains a malformed token")
	}
	if credential.Source != "ephemeral_scan_role" && credential.Source != "external_read_only_grant" {
		return errors.New("credential source is not a scanner-only source")
	}
	if !credential.ExpiresAt.After(now) || credential.ExpiresAt.After(now.Add(maximumTokenLife)) {
		return errors.New("credential is expired or exceeds the short-lived scanner window")
	}
	return nil
}

func validateOutputDirectory(path string) error {
	metadata, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect evidence output: %w", err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
		return errors.New("evidence output must be a runtime-owned directory")
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("path is not absolute")
	}
	metadata, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() || metadata.Size() > maximum {
		return nil, errors.New("input is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maximum {
		return nil, errors.New("input exceeds its byte limit")
	}
	return payload, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func safeText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

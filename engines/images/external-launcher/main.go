// ai-security-scanner-external-launcher is the non-shell capability boundary
// for the managed Naabu, httpx, and Nuclei images. It translates only the
// immutable per-asset grants written by the desktop application into fixed
// scanner invocations. Every child process is independently bounded by the
// grant that authorized it and can reach the target only through the managed
// SOCKS gateway.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	scopeMountPath         = "/run/ai-security-scanner/scope.json"
	outputMountPath        = "/output"
	templateRootPath       = "/opt/nuclei-templates"
	templateRevision       = "24858b4bfabfa86f0bcfd36aea24fb535152b012"
	templateRevisionMarker = "/opt/nuclei-templates/AI_SECURITY_SCANNER_REVISION"
	maxScopeBytes          = 4 * 1024 * 1024
	maxEvidenceBytes       = 512 * 1024 * 1024
	maxEvidenceLineBytes   = 16 * 1024 * 1024
	maxTemplateBytes       = 1024 * 1024
	maxTemplateHeaderBytes = 128 * 1024
	maxAssets              = 4096
	maxIdentifiers         = 128
	maxGrantsPerAsset      = 16
	maxResolvedAddresses   = 4096
	managedGatewayPort     = "1080"
)

type scopeDocument struct {
	SchemaVersion string       `json:"schema_version"`
	EngineID      string       `json:"engine_id"`
	GeneratedAt   time.Time    `json:"generated_at"`
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
	ID                     string         `json:"id"`
	Permission             string         `json:"permission"`
	ConfirmedBy            string         `json:"confirmed_by"`
	ConfirmedAt            time.Time      `json:"confirmed_at"`
	ExpiresAt              *time.Time     `json:"expires_at"`
	AuthorizationReference *string        `json:"authorization_reference"`
	ExternalScope          *externalScope `json:"external_scope"`
	ResolvedAddresses      []string       `json:"resolved_addresses"`
}

type externalScope struct {
	ID                     string          `json:"id"`
	CaseID                 string          `json:"case_id"`
	AssetID                string          `json:"asset_id"`
	Target                 canonicalTarget `json:"target"`
	Ports                  []uint16        `json:"ports"`
	Protocol               string          `json:"protocol"`
	Activity               string          `json:"activity"`
	RatePolicy             ratePolicy      `json:"rate_policy"`
	TemplatePolicy         templatePolicy  `json:"template_policy"`
	AssertedAuthority      string          `json:"asserted_authority"`
	ApprovedBy             string          `json:"approved_by"`
	ApprovedAt             time.Time       `json:"approved_at"`
	ExpiresAt              time.Time       `json:"expires_at"`
	AllowSensitiveNetworks bool            `json:"allow_sensitive_networks"`
}

type canonicalTarget struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type ratePolicy struct {
	RequestsPerSecond uint16 `json:"requests_per_second"`
	Concurrency       uint16 `json:"concurrency"`
	TimeoutSeconds    uint32 `json:"timeout_seconds"`
}

type templatePolicy struct {
	Revision               string   `json:"revision"`
	AllowedTemplateIDs     []string `json:"allowed_template_ids"`
	AllowHeadless          bool     `json:"allow_headless"`
	AllowOutOfBand         bool     `json:"allow_out_of_band"`
	AllowFuzzing           bool     `json:"allow_fuzzing"`
	AllowFileUpload        bool     `json:"allow_file_upload"`
	AllowDenialOfService   bool     `json:"allow_denial_of_service"`
	AllowCredentialAttacks bool     `json:"allow_credential_attacks"`
}

type scanUnit struct {
	AssetID           string
	Grant             externalScope
	Port              uint16
	FrozenAddress     string
	ResolvedAddresses []string
}

type invocation struct {
	Program string
	Args    []string
	Env     []string
	Expiry  time.Time
	Timeout time.Duration
}

type boundedBuffer struct {
	bytes.Buffer
	remaining int
}

var errTemplateIDAbsent = errors.New("template has no bounded id header")

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if len(value) > buffer.remaining {
		value = value[:buffer.remaining]
	}
	written, err := buffer.Buffer.Write(value)
	buffer.remaining -= written
	if err != nil {
		return written, err
	}
	return originalLength, nil
}

func main() {
	if err := run(os.Args[1:], time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "external engine launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string, now time.Time) error {
	flags := flag.NewFlagSet("ai-security-scanner-external-launcher", flag.ContinueOnError)
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
	if *scopePath != scopeMountPath || *outputPath != outputMountPath {
		return errors.New("scope and output paths must use the runtime-owned mounts")
	}
	if err := validateOutputDirectory(*outputPath); err != nil {
		return err
	}
	proxy, naabuProxy, err := managedProxy(os.Getenv("AI_SECURITY_SCANNER_PROXY"))
	if err != nil {
		return err
	}
	document, err := loadScope(*scopePath, *engineID)
	if err != nil {
		return err
	}
	units, err := validateAndPlan(document, *engineID, now)
	if err != nil {
		return err
	}

	temporaryRoot, err := os.MkdirTemp("/tmp", "ai-security-scanner-external-")
	if err != nil {
		return fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		return fmt.Errorf("restrict private temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)

	var templates map[string]string
	if *engineID == "nuclei" {
		if err := verifyTemplateRevision(templateRevisionMarker); err != nil {
			return err
		}
		templates, err = loadTemplateIndex(filepath.Join(templateRootPath, "http"))
		if err != nil {
			return err
		}
	}

	finalPath := filepath.Join(*outputPath, *engineID+".jsonl")
	final, err := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive evidence file: %w", err)
	}
	complete := false
	defer func() {
		_ = final.Close()
		if !complete {
			_ = os.Remove(finalPath)
		}
	}()
	writer := bufio.NewWriterSize(final, 64*1024)
	written := int64(0)
	environment := childEnvironment(proxy, temporaryRoot)
	nucleiProxy := nucleiCompatibleProxy(proxy)
	if *engineID == "nuclei" {
		// Nuclei v3.11.1 calls the same remote-name SOCKS5 protocol "socks5";
		// its parser rejects the conventional socks5h URL spelling. The endpoint
		// was already reduced above to the runtime-owned literal bridge IP:1080.
		environment = childEnvironment(nucleiProxy, temporaryRoot)
	}

	for index, unit := range units {
		if !now.Before(unit.Grant.ExpiresAt) || !time.Now().UTC().Before(unit.Grant.ExpiresAt) {
			return fmt.Errorf("scope grant %s expired before its independent invocation", unit.Grant.ID)
		}
		temporaryOutput := filepath.Join(temporaryRoot, fmt.Sprintf("result-%06d.jsonl", index))
		var command invocation
		switch *engineID {
		case "naabu":
			command = naabuInvocation(unit, naabuProxy, temporaryOutput, environment)
		case "httpx":
			command, err = httpxInvocation(unit, proxy, temporaryOutput, environment)
		case "nuclei":
			var templatePaths []string
			templatePaths, err = selectedTemplatePaths(unit.Grant.TemplatePolicy, templates)
			if err == nil {
				command, err = nucleiInvocation(unit, nucleiProxy, temporaryOutput, environment, temporaryRoot, index, templatePaths)
			}
		}
		if err != nil {
			return err
		}
		if err := runCommand(command); err != nil {
			return fmt.Errorf("%s grant %s invocation failed: %w", *engineID, unit.Grant.ID, err)
		}
		if err := normalizeEvidence(temporaryOutput, writer, &written, *engineID, unit); err != nil {
			return err
		}
		if err := os.Remove(temporaryOutput); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove normalized temporary evidence: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush evidence: %w", err)
	}
	if err := final.Sync(); err != nil {
		return fmt.Errorf("sync evidence: %w", err)
	}
	if err := final.Close(); err != nil {
		return fmt.Errorf("close evidence: %w", err)
	}
	complete = true
	return nil
}

func supportedEngine(engineID string) bool {
	return engineID == "naabu" || engineID == "httpx" || engineID == "nuclei"
}

func loadScope(path, expectedEngine string) (*scopeDocument, error) {
	value, err := readBoundedRegularFile(path, maxScopeBytes)
	if err != nil {
		return nil, fmt.Errorf("read immutable scope: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var document scopeDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("scope document is malformed")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errors.New("scope document has trailing data")
	}
	if document.SchemaVersion != "1" || document.EngineID != expectedEngine || len(document.Assets) == 0 || len(document.Assets) > maxAssets {
		return nil, errors.New("scope document version, engine, or asset count is invalid")
	}
	return &document, nil
}

func validateAndPlan(document *scopeDocument, engineID string, now time.Time) ([]scanUnit, error) {
	if document.GeneratedAt.IsZero() || document.GeneratedAt.After(now.Add(5*time.Minute)) {
		return nil, errors.New("scope document timestamp is invalid or future-dated")
	}
	expectedPermission := "low_impact_external_connection"
	expectedActivity := "low_impact_external"
	if engineID == "nuclei" {
		expectedPermission = "active_external_testing"
		expectedActivity = "active_external"
	}
	seenAssets := make(map[string]struct{}, len(document.Assets))
	seenGrants := make(map[string]struct{})
	caseID := ""
	units := make([]scanUnit, 0, len(document.Assets))
	for _, asset := range document.Assets {
		if !safeText(asset.ID, 256) || !safeText(asset.Name, 4096) || !supportedAssetKind(engineID, asset.Kind) {
			return nil, errors.New("scope contains an invalid or unsupported asset")
		}
		if _, exists := seenAssets[asset.ID]; exists {
			return nil, errors.New("scope contains a duplicate asset")
		}
		seenAssets[asset.ID] = struct{}{}
		if asset.Provider != nil || asset.Region != nil || len(asset.Identifiers) == 0 || len(asset.Identifiers) > maxIdentifiers || len(asset.Grants) == 0 || len(asset.Grants) > maxGrantsPerAsset {
			return nil, errors.New("external asset provider, identifier, or grant closure is invalid")
		}
		for _, grant := range asset.Grants {
			if grant.Permission != expectedPermission || grant.ExternalScope == nil {
				return nil, errors.New("scope contains a grant outside the engine permission closure")
			}
			external := *grant.ExternalScope
			if err := validateGrant(asset, grant, external, engineID, expectedActivity, now); err != nil {
				return nil, err
			}
			if _, exists := seenGrants[grant.ID]; exists {
				return nil, errors.New("scope contains a duplicate grant")
			}
			seenGrants[grant.ID] = struct{}{}
			if caseID == "" {
				caseID = external.CaseID
			} else if caseID != external.CaseID {
				return nil, errors.New("one execution cannot combine grants from different cases")
			}
			resolvedAddresses := append([]string(nil), grant.ResolvedAddresses...)
			if engineID == "naabu" {
				for _, address := range resolvedAddresses {
					units = append(units, scanUnit{
						AssetID: asset.ID, Grant: external, FrozenAddress: address,
						ResolvedAddresses: resolvedAddresses,
					})
				}
			} else {
				for _, port := range external.Ports {
					units = append(units, scanUnit{
						AssetID: asset.ID, Grant: external, Port: port,
						ResolvedAddresses: resolvedAddresses,
					})
				}
			}
		}
	}
	sort.Slice(units, func(left, right int) bool {
		if units[left].AssetID != units[right].AssetID {
			return units[left].AssetID < units[right].AssetID
		}
		if units[left].Grant.ID != units[right].Grant.ID {
			return units[left].Grant.ID < units[right].Grant.ID
		}
		if units[left].Port != units[right].Port {
			return units[left].Port < units[right].Port
		}
		return units[left].FrozenAddress < units[right].FrozenAddress
	})
	return units, nil
}

func validateGrant(asset scopeAsset, grant scopeGrant, external externalScope, engineID, expectedActivity string, now time.Time) error {
	if !safeText(grant.ID, 256) || !safeText(grant.ConfirmedBy, 1024) || grant.AuthorizationReference == nil || !safeText(*grant.AuthorizationReference, 1000) {
		return errors.New("external grant identity or written authorization is invalid")
	}
	if external.ID != grant.ID || external.AssetID != asset.ID || !safeText(external.CaseID, 256) || external.ApprovedBy != grant.ConfirmedBy || !safeText(external.AssertedAuthority, 4096) {
		return errors.New("structured external policy does not match its asset grant")
	}
	if grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(external.ExpiresAt) || !grant.ConfirmedAt.Equal(external.ApprovedAt) {
		return errors.New("external policy timestamps diverge from the grant")
	}
	if external.ApprovedAt.IsZero() || external.ApprovedAt.After(now.Add(5*time.Minute)) || !external.ExpiresAt.After(now) || !external.ExpiresAt.After(external.ApprovedAt) || external.ExpiresAt.Sub(external.ApprovedAt) > 30*24*time.Hour {
		return errors.New("external grant is expired, future-dated, or exceeds thirty days")
	}
	if external.Activity != expectedActivity || external.Protocol == "udp" {
		return errors.New("external activity or transport protocol does not match the engine")
	}
	if engineID != "naabu" && external.Protocol != "http" && external.Protocol != "https" {
		return errors.New("HTTP engines require an exact HTTP or HTTPS protocol grant")
	}
	if engineID == "naabu" && external.Protocol != "tcp" && external.Protocol != "tls" && external.Protocol != "http" && external.Protocol != "https" {
		return errors.New("Naabu requires a TCP-based protocol grant")
	}
	canonical, err := validateCanonicalTarget(external.Target)
	if err != nil {
		return err
	}
	if engineID != "naabu" && external.Target.Kind == "network" {
		return errors.New("HTTP engines do not expand network targets")
	}
	for _, identifier := range asset.Identifiers {
		if !safeText(identifier.Namespace, 256) || identifier.Value != canonical {
			return errors.New("asset identifiers are not closed over the canonical external target")
		}
	}
	if err := validatePorts(external.Ports); err != nil {
		return err
	}
	if err := validateResolvedAddresses(grant.ResolvedAddresses, external.Target); err != nil {
		return err
	}
	if err := validateRatePolicy(external.RatePolicy, expectedActivity); err != nil {
		return err
	}
	return validateTemplatePolicy(external.TemplatePolicy, engineID)
}

func supportedAssetKind(engineID, kind string) bool {
	switch engineID {
	case "naabu":
		return kind == "host" || kind == "ip_address"
	case "httpx", "nuclei":
		return kind == "domain" || kind == "ip_address" || kind == "web_service"
	default:
		return false
	}
}

func validateCanonicalTarget(target canonicalTarget) (string, error) {
	if !safeText(target.Value, 2048) || strings.Contains(target.Value, "*") {
		return "", errors.New("external target is empty, wildcarded, or malformed")
	}
	switch target.Kind {
	case "hostname":
		if target.Value != strings.ToLower(target.Value) || strings.HasSuffix(target.Value, ".") || len(target.Value) > 253 || !strings.Contains(target.Value, ".") {
			return "", errors.New("external hostname is not canonical")
		}
		for _, label := range strings.Split(target.Value, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", errors.New("external hostname is malformed")
			}
			for _, character := range label {
				if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
					return "", errors.New("external hostname contains unsupported characters")
				}
			}
		}
		return target.Value, nil
	case "address":
		parsed := net.ParseIP(target.Value)
		if parsed == nil || parsed.String() != target.Value {
			return "", errors.New("external address is not canonical")
		}
		return parsed.String(), nil
	case "network":
		_, network, err := net.ParseCIDR(target.Value)
		if err != nil || network.String() != target.Value {
			return "", errors.New("external network is not canonical")
		}
		return network.String(), nil
	default:
		return "", errors.New("external target kind is unsupported")
	}
}

func validatePorts(ports []uint16) error {
	if len(ports) == 0 || len(ports) > 65535 {
		return errors.New("external grant requires a bounded non-empty port set")
	}
	previous := uint16(0)
	for index, port := range ports {
		if port == 0 || (index > 0 && port <= previous) {
			return errors.New("external ports must be non-zero, unique, and sorted")
		}
		previous = port
	}
	return nil
}

func validateResolvedAddresses(addresses []string, target canonicalTarget) error {
	if len(addresses) == 0 || len(addresses) > maxResolvedAddresses {
		return errors.New("external grant requires a bounded non-empty frozen address set")
	}
	seen := make(map[string]struct{}, len(addresses))
	var targetAddress net.IP
	var targetNetwork *net.IPNet
	if target.Kind == "address" {
		targetAddress = net.ParseIP(target.Value)
	}
	if target.Kind == "network" {
		_, targetNetwork, _ = net.ParseCIDR(target.Value)
	}
	for _, value := range addresses {
		parsed := net.ParseIP(value)
		if parsed == nil || parsed.String() != value {
			return errors.New("frozen address set contains a non-canonical IP address")
		}
		if _, exists := seen[value]; exists {
			return errors.New("frozen address set contains a duplicate IP address")
		}
		seen[value] = struct{}{}
		if targetAddress != nil && !parsed.Equal(targetAddress) {
			return errors.New("frozen address is outside the exact address target")
		}
		if targetNetwork != nil && !targetNetwork.Contains(parsed) {
			return errors.New("frozen address is outside the approved network target")
		}
	}
	return nil
}

func validateRatePolicy(policy ratePolicy, activity string) error {
	maxRate, maxConcurrency, maxTimeout := uint16(25), uint16(10), uint32(1800)
	if activity == "active_external" {
		maxRate, maxConcurrency, maxTimeout = 10, 5, 3600
	}
	if policy.RequestsPerSecond == 0 || policy.RequestsPerSecond > maxRate || policy.Concurrency == 0 || policy.Concurrency > maxConcurrency || policy.TimeoutSeconds == 0 || policy.TimeoutSeconds > maxTimeout {
		return errors.New("external rate, concurrency, or timeout exceeds its activity class")
	}
	return nil
}

func validateTemplatePolicy(policy templatePolicy, engineID string) error {
	if policy.AllowHeadless || policy.AllowOutOfBand || policy.AllowFuzzing || policy.AllowFileUpload || policy.AllowDenialOfService || policy.AllowCredentialAttacks {
		return errors.New("prohibited template capability was enabled")
	}
	if engineID != "nuclei" {
		if policy.Revision != "not_applicable" || len(policy.AllowedTemplateIDs) != 0 {
			return errors.New("non-template engine received a template selection")
		}
		return nil
	}
	if policy.Revision != "nuclei-templates@"+templateRevision || len(policy.AllowedTemplateIDs) == 0 || len(policy.AllowedTemplateIDs) > 1000 {
		return errors.New("Nuclei policy does not match the embedded exact template revision or bounded allowlist")
	}
	seen := make(map[string]struct{}, len(policy.AllowedTemplateIDs))
	for _, id := range policy.AllowedTemplateIDs {
		if !safeTemplateID(id) {
			return errors.New("Nuclei template allowlist contains an invalid exact identifier")
		}
		if _, exists := seen[id]; exists {
			return errors.New("Nuclei template allowlist contains a duplicate identifier")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func managedProxy(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5h" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != managedGatewayPort || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("managed SOCKS gateway endpoint is absent or malformed")
	}
	if net.ParseIP(parsed.Hostname()) == nil {
		return "", "", errors.New("managed SOCKS gateway must use the frozen bridge address")
	}
	canonical := "socks5h://" + net.JoinHostPort(parsed.Hostname(), parsed.Port())
	return canonical, net.JoinHostPort(parsed.Hostname(), parsed.Port()), nil
}

func nucleiCompatibleProxy(managed string) string {
	return "socks5://" + strings.TrimPrefix(managed, "socks5h://")
}

func childEnvironment(proxy, temporaryRoot string) []string {
	return []string{
		"AI_SECURITY_SCANNER_PROXY=" + proxy,
		"ALL_PROXY=" + proxy,
		"all_proxy=" + proxy,
		"HTTP_PROXY=" + proxy,
		"http_proxy=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"https_proxy=" + proxy,
		"NO_PROXY=",
		"no_proxy=",
		"DISABLE_STDOUT=1",
		"HOME=" + temporaryRoot,
		"XDG_CACHE_HOME=" + filepath.Join(temporaryRoot, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(temporaryRoot, "config"),
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
}

func naabuInvocation(unit scanUnit, proxy, output string, environment []string) invocation {
	ports := make([]string, 0, len(unit.Grant.Ports))
	for _, port := range unit.Grant.Ports {
		ports = append(ports, strconv.Itoa(int(port)))
	}
	return invocation{
		Program: "/usr/local/bin/naabu",
		Args: []string{
			"-host", unit.FrozenAddress,
			"-port", strings.Join(ports, ","),
			"-scan-type", "c",
			"-proxy", proxy,
			"-rate", strconv.Itoa(int(unit.Grant.RatePolicy.RequestsPerSecond)),
			"-c", strconv.Itoa(int(unit.Grant.RatePolicy.Concurrency)),
			"-timeout", (time.Duration(unit.Grant.RatePolicy.TimeoutSeconds) * time.Second).String(),
			"-retries", "0",
			"-json", "-output", output,
			"-no-stdin", "-disable-update-check", "-silent",
		},
		Env: environment, Expiry: unit.Grant.ExpiresAt, Timeout: time.Duration(unit.Grant.RatePolicy.TimeoutSeconds) * time.Second,
	}
}

func httpxInvocation(unit scanUnit, proxy, output string, environment []string) (invocation, error) {
	target, err := targetURL(unit)
	if err != nil {
		return invocation{}, err
	}
	return invocation{
		Program: "/usr/local/bin/httpx",
		Args: []string{
			"-target", target,
			"-proxy", proxy,
			"-rate-limit", strconv.Itoa(int(unit.Grant.RatePolicy.RequestsPerSecond)),
			"-threads", strconv.Itoa(int(unit.Grant.RatePolicy.Concurrency)),
			"-timeout", strconv.Itoa(int(unit.Grant.RatePolicy.TimeoutSeconds)),
			"-retries", "0",
			"-json", "-output", output,
			"-status-code", "-omit-body", "-no-fallback-scheme",
			"-no-stdin", "-disable-update-check", "-silent", "-no-color",
		},
		Env: environment, Expiry: unit.Grant.ExpiresAt, Timeout: time.Duration(unit.Grant.RatePolicy.TimeoutSeconds) * time.Second,
	}, nil
}

func nucleiInvocation(unit scanUnit, proxy, output string, environment []string, temporaryRoot string, index int, templatePaths []string) (invocation, error) {
	target, err := targetURL(unit)
	if err != nil {
		return invocation{}, err
	}
	templatesFile := filepath.Join(temporaryRoot, fmt.Sprintf("templates-%06d.txt", index))
	idsFile := filepath.Join(temporaryRoot, fmt.Sprintf("template-ids-%06d.txt", index))
	if err := writeExclusiveLines(templatesFile, templatePaths); err != nil {
		return invocation{}, err
	}
	if err := writeExclusiveLines(idsFile, unit.Grant.TemplatePolicy.AllowedTemplateIDs); err != nil {
		return invocation{}, err
	}
	concurrency := strconv.Itoa(int(unit.Grant.RatePolicy.Concurrency))
	return invocation{
		Program: "/usr/local/bin/nuclei",
		Args: []string{
			"-target", target,
			"-templates", templatesFile,
			"-template-id", idsFile,
			"-type", "http",
			"-proxy", proxy,
			"-rate-limit", strconv.Itoa(int(unit.Grant.RatePolicy.RequestsPerSecond)),
			"-bulk-size", concurrency,
			"-concurrency", concurrency,
			"-timeout", strconv.Itoa(int(unit.Grant.RatePolicy.TimeoutSeconds)),
			"-retries", "0",
			"-jsonl-export", output,
			"-no-httpx", "-no-interactsh", "-disable-redirects",
			"-no-stdin", "-disable-update-check",
			"-omit-raw", "-omit-template", "-silent", "-no-color",
		},
		Env: environment, Expiry: unit.Grant.ExpiresAt, Timeout: time.Duration(unit.Grant.RatePolicy.TimeoutSeconds) * time.Second,
	}, nil
}

func targetURL(unit scanUnit) (string, error) {
	if unit.Port == 0 || (unit.Grant.Protocol != "http" && unit.Grant.Protocol != "https") {
		return "", errors.New("HTTP invocation has no exact protocol and port")
	}
	host := unit.Grant.Target.Value
	if unit.Grant.Target.Kind == "address" && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s://%s:%d", unit.Grant.Protocol, host, unit.Port), nil
}

func runCommand(plan invocation) error {
	remaining := time.Until(plan.Expiry)
	if remaining <= 0 {
		return errors.New("scope grant expired before scanner start")
	}
	timeout := plan.Timeout
	if remaining < timeout {
		timeout = remaining
	}
	commandContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, plan.Program, plan.Args...)
	command.Env = plan.Env
	command.Stdin = nil
	command.Stdout = io.Discard
	stderr := &boundedBuffer{remaining: 64 * 1024}
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 2 * time.Second
	if err := command.Run(); err != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return errors.New("scanner exceeded the frozen total timeout")
		}
		return fmt.Errorf("scanner exited unsuccessfully%s", sanitizedStderr(stderr.String()))
	}
	return nil
}

func sanitizedStderr(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var cleaned strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\t' || (character >= 0x20 && character != 0x7f) {
			cleaned.WriteRune(character)
		}
		if cleaned.Len() >= 1024 {
			break
		}
	}
	return ": " + cleaned.String()
}

func normalizeEvidence(path string, destination *bufio.Writer, written *int64, engineID string, unit scanUnit) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open scanner evidence: %w", err)
	}
	defer file.Close()
	metadata, err := file.Stat()
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() > maxEvidenceBytes {
		return errors.New("scanner evidence is not a bounded regular file")
	}
	scanner := bufio.NewScanner(io.LimitReader(file, maxEvidenceBytes+1))
	scanner.Buffer(make([]byte, 64*1024), maxEvidenceLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(line, &object); err != nil || object == nil {
			return errors.New("scanner emitted malformed JSONL evidence")
		}
		if err := validateEvidenceObject(engineID, object, unit); err != nil {
			return err
		}
		assetValue, _ := json.Marshal(unit.AssetID)
		grantValue, _ := json.Marshal(unit.Grant.ID)
		targetValue, _ := json.Marshal(unit.Grant.Target.Value)
		object["asset_id"] = assetValue
		object["scope_grant_id"] = grantValue
		object["scope_target"] = targetValue
		for _, key := range []string{"request", "response", "template", "curl-command", "body", "raw"} {
			delete(object, key)
		}
		normalized, err := json.Marshal(object)
		if err != nil {
			return errors.New("scanner evidence could not be normalized")
		}
		normalized = append(normalized, '\n')
		if *written+int64(len(normalized)) > maxEvidenceBytes {
			return errors.New("normalized scanner evidence exceeds its aggregate limit")
		}
		if _, err := destination.Write(normalized); err != nil {
			return fmt.Errorf("write normalized evidence: %w", err)
		}
		*written += int64(len(normalized))
	}
	if err := scanner.Err(); err != nil {
		return errors.New("scanner evidence contains an overlong or unreadable record")
	}
	return nil
}

func validateEvidenceObject(engineID string, object map[string]json.RawMessage, unit scanUnit) error {
	if existing, ok := object["asset_id"]; ok {
		var assetID string
		if json.Unmarshal(existing, &assetID) != nil || assetID != unit.AssetID {
			return errors.New("scanner attempted to attribute evidence to another asset")
		}
	}
	switch engineID {
	case "naabu":
		port, err := jsonPort(object["port"])
		if err != nil || !containsPort(unit.Grant.Ports, port) {
			return errors.New("Naabu emitted a port outside its independent grant")
		}
		if protocol, ok := jsonString(object["protocol"]); ok && strings.ToLower(protocol) != "tcp" {
			return errors.New("Naabu emitted a non-TCP observation")
		}
		protocol, _ := json.Marshal("tcp")
		object["protocol"] = protocol
		observed, ok := firstJSONString(object, "host", "ip")
		if !ok || !observedFrozenAddressMatches(unit.FrozenAddress, observed) {
			return errors.New("Naabu evidence target is outside its independent grant")
		}
	case "httpx":
		observed, ok := firstJSONString(object, "url", "input")
		if !ok || validateObservedURL(observed, unit) != nil {
			return errors.New("httpx evidence target is outside its independent grant")
		}
	case "nuclei":
		id, ok := firstJSONString(object, "template-id", "template_id", "templateID")
		if !ok || !containsString(unit.Grant.TemplatePolicy.AllowedTemplateIDs, id) {
			return errors.New("Nuclei emitted a template outside the frozen allowlist")
		}
		observed, ok := firstJSONString(object, "matched-at", "matched_at", "url", "host")
		if !ok || validateObservedURL(observed, unit) != nil {
			return errors.New("Nuclei evidence target is outside its independent grant")
		}
	default:
		return errors.New("unsupported evidence profile")
	}
	return nil
}

func validateObservedURL(value string, unit scanUnit) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Scheme != unit.Grant.Protocol || parsed.Hostname() == "" {
		return errors.New("observed URL is malformed")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || uint16(parsedPort) != unit.Port || !observedTargetMatches(unit, parsed.Hostname()) {
		return errors.New("observed URL endpoint differs from its frozen target")
	}
	return nil
}

func observedFrozenAddressMatches(expected, observed string) bool {
	parsed := net.ParseIP(observed)
	return parsed != nil && parsed.String() == observed && observed == expected
}

func observedTargetMatches(unit scanUnit, observed string) bool {
	target := unit.Grant.Target
	if parsed := net.ParseIP(observed); parsed != nil {
		canonical := parsed.String()
		if canonical != observed || !containsString(unit.ResolvedAddresses, canonical) {
			return false
		}
		switch target.Kind {
		case "address":
			return canonical == target.Value
		case "network":
			_, network, err := net.ParseCIDR(target.Value)
			return err == nil && network.Contains(parsed)
		case "hostname":
			return true
		default:
			return false
		}
	}
	switch target.Kind {
	case "hostname":
		return strings.EqualFold(strings.TrimSuffix(observed, "."), target.Value)
	case "address", "network":
		return false
	default:
		return false
	}
}

func verifyTemplateRevision(path string) error {
	value, err := readBoundedRegularFile(path, 256)
	if err != nil || strings.TrimSpace(string(value)) != templateRevision {
		return errors.New("embedded Nuclei template revision marker is absent or mismatched")
	}
	return nil
}

func loadTemplateIndex(root string) (map[string]string, error) {
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("embedded Nuclei template root is unavailable")
	}
	index := make(map[string]string)
	err = filepath.WalkDir(canonicalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("embedded Nuclei template tree contains a symlink")
		}
		if entry.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
			return nil
		}
		metadata, err := entry.Info()
		if err != nil || !metadata.Mode().IsRegular() {
			return errors.New("embedded Nuclei template is not a regular file")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		header, readErr := io.ReadAll(io.LimitReader(file, maxTemplateHeaderBytes))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errors.New("embedded Nuclei template index could not be read")
		}
		id, err := extractTemplateID(header)
		if err != nil {
			if errors.Is(err, errTemplateIDAbsent) {
				return nil
			}
			return fmt.Errorf("index template %s: %w", filepath.Base(path), err)
		}
		if previous, exists := index[id]; exists && previous != path {
			return fmt.Errorf("embedded Nuclei template id %s is duplicated", id)
		}
		index[id] = path
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("build exact Nuclei template index: %w", err)
	}
	return index, nil
}

func extractTemplateID(value []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(value))
	scanner.Buffer(make([]byte, 4096), maxTemplateHeaderBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "id:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			id = strings.Trim(id, "\"'")
			if safeTemplateID(id) {
				return id, nil
			}
			return "", errors.New("template id is malformed")
		}
	}
	return "", errTemplateIDAbsent
}

func selectedTemplatePaths(policy templatePolicy, index map[string]string) ([]string, error) {
	paths := make([]string, 0, len(policy.AllowedTemplateIDs))
	for _, id := range policy.AllowedTemplateIDs {
		path, exists := index[id]
		if !exists {
			return nil, fmt.Errorf("Nuclei template %s is not in the embedded exact revision", id)
		}
		if err := validateSafeTemplate(path, id); err != nil {
			return nil, fmt.Errorf("Nuclei template %s is prohibited: %w", id, err)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func validateSafeTemplate(path, expectedID string) error {
	value, err := readBoundedRegularFile(path, maxTemplateBytes)
	if err != nil {
		return err
	}
	id, err := extractTemplateID(value)
	if err != nil || id != expectedID {
		return errors.New("template identity changed after indexing")
	}
	lower := strings.ToLower(string(value))
	for _, token := range []string{"interactsh", "{{oast", "multipart/form-data", "{{file", "{{env", "race_count:"} {
		if strings.Contains(lower, token) {
			return fmt.Errorf("contains denied capability %q", token)
		}
	}
	deniedTopLevel := map[string]bool{"headless": true, "dns": true, "network": true, "file": true, "javascript": true, "code": true, "ssl": true, "websocket": true, "workflows": true, "flow": true}
	deniedTags := map[string]bool{"headless": true, "oast": true, "fuzz": true, "fuzzing": true, "dast": true, "dos": true, "intrusive": true, "bruteforce": true, "brute-force": true, "credential-stuffing": true, "default-login": true, "file-upload": true, "upload": true}
	httpFound, methodFound, maxRequest := false, false, 0
	scanner := bufio.NewScanner(strings.NewReader(lower))
	scanner.Buffer(make([]byte, 64*1024), maxEvidenceLineBytes)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(raw) == len(strings.TrimLeft(raw, " \t")) {
			if separator := strings.IndexByte(trimmed, ':'); separator > 0 {
				key := strings.TrimSpace(trimmed[:separator])
				if deniedTopLevel[key] {
					return fmt.Errorf("uses denied top-level protocol %s", key)
				}
				if key == "http" {
					httpFound = true
				}
			}
		}
		withoutDash := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		for _, prefix := range []string{"payloads:", "attack:", "fuzzing:", "body:", "raw:"} {
			if strings.HasPrefix(withoutDash, prefix) {
				return fmt.Errorf("uses denied request primitive %s", strings.TrimSuffix(prefix, ":"))
			}
		}
		if strings.HasPrefix(withoutDash, "method:") {
			method := strings.Trim(strings.TrimSpace(strings.TrimPrefix(withoutDash, "method:")), "\"'")
			if method != "get" && method != "head" {
				return fmt.Errorf("uses non-read-only HTTP method %s", method)
			}
			methodFound = true
		}
		if strings.HasPrefix(withoutDash, "redirects:") || strings.HasPrefix(withoutDash, "host-redirects:") {
			if strings.HasSuffix(withoutDash, "true") {
				return errors.New("enables redirects inside the template")
			}
		}
		if strings.HasPrefix(withoutDash, "max-request:") {
			value := strings.TrimSpace(strings.TrimPrefix(withoutDash, "max-request:"))
			maxRequest, _ = strconv.Atoi(value)
		}
		if strings.HasPrefix(withoutDash, "tags:") {
			for _, tag := range strings.Split(strings.TrimSpace(strings.TrimPrefix(withoutDash, "tags:")), ",") {
				if deniedTags[strings.Trim(strings.TrimSpace(tag), "[]\"'")] {
					return fmt.Errorf("contains denied template tag %s", tag)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("template contains an overlong YAML line")
	}
	if !httpFound || !methodFound || maxRequest < 1 || maxRequest > 20 {
		return errors.New("template is not bounded to GET/HEAD HTTP with max-request 1..20")
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 || metadata.Size() > maximum {
		return nil, errors.New("file is absent, non-regular, symlinked, or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("file exceeds its read limit")
	}
	return value, nil
}

func validateOutputDirectory(path string) error {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 {
		return errors.New("output mount is not a regular directory")
	}
	return nil
}

func writeExclusiveLines(path string, lines []string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private scanner input: %w", err)
	}
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if line == "" || strings.ContainsAny(line, "\r\n\x00") {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("private scanner input contains an unsafe line")
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func safeText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func safeTemplateID(value string) bool {
	if !safeText(value, 256) || value == "*" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._:/-", character) {
			return false
		}
	}
	return true
}

func containsPort(values []uint16, expected uint16) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= expected })
	return index < len(values) && values[index] == expected
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func jsonString(value json.RawMessage) (string, bool) {
	var result string
	if value == nil || json.Unmarshal(value, &result) != nil || result == "" {
		return "", false
	}
	return result, true
}

func firstJSONString(object map[string]json.RawMessage, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := jsonString(object[key]); ok {
			return value, true
		}
	}
	return "", false
}

func jsonPort(value json.RawMessage) (uint16, error) {
	if value == nil {
		return 0, errors.New("port is absent")
	}
	var numeric uint16
	if json.Unmarshal(value, &numeric) == nil && numeric != 0 {
		return numeric, nil
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		parsed, err := strconv.ParseUint(text, 10, 16)
		return uint16(parsed), err
	}
	return 0, errors.New("port is malformed")
}

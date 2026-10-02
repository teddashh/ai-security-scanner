// ai-security-scanner-cloud-launcher is the non-shell capability boundary used
// by the managed cloud engine images. It accepts only the immutable scope and
// short-lived credential documents mounted by the desktop runtime, selects one
// fixed provider profile from the exact credential-key set, and starts only a
// project-owned static command plan.
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	credentialPath          = "/run/ai-security-scanner/credentials.json"
	awsRegionalSTSEndpoint  = "https://sts.us-east-1.amazonaws.com/"
	awsGlobalSTSEndpoint    = "https://sts.amazonaws.com/"
	awsSTSRegion            = "us-east-1"
	azureManagementRoot     = "https://management.azure.com"
	gcpResourceManagerRoot  = "https://cloudresourcemanager.googleapis.com"
	maxCredentialSize       = 256 * 1024
	maxScopeSize            = 4 * 1024 * 1024
	maxOutputFileSize       = 512 * 1024 * 1024
	maxProviderResponseSize = 256 * 1024
	maxJSONRecordSize       = 8 * 1024 * 1024
	maxJSONRecords          = 1_000_000
	minimumCredentialTTL    = 5 * time.Minute
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

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
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
	credentials, selectedProvider, credentialExpiresAt, err := loadCredentials(credentialPath)
	if err != nil {
		return err
	}
	if err := validateProviderForEngine(*engineID, selectedProvider, scope); err != nil {
		return err
	}
	if err := validateScopePermissions(scope, *engineID); err != nil {
		return err
	}
	providerTarget, err := expectedProviderTarget(scope, selectedProvider)
	if err != nil {
		return err
	}
	verificationTime := time.Now().UTC()
	if err := validateCredentialLifetime(credentialExpiresAt, verificationTime); err != nil {
		return err
	}
	providerClient := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("provider identity verification refused a redirect")
		},
	}
	switch selectedProvider {
	case providerAWS:
		if err := verifyAWSCallerIdentity(providerClient, awsSTSEndpointForEngine(*engineID), credentials, providerTarget, verificationTime); err != nil {
			return err
		}
	case providerAzure:
		if err := verifyAzureSubscription(providerClient, azureManagementRoot, credentials["AZURE_ACCESS_TOKEN"], providerTarget); err != nil {
			return err
		}
	case providerGCP:
		if err := verifyGCPProject(providerClient, gcpResourceManagerRoot, credentials["GOOGLE_OAUTH_ACCESS_TOKEN"], providerTarget); err != nil {
			return err
		}
	default:
		return errors.New("unreachable provider preflight")
	}
	// An idle preflight connection would hold a gateway slot through the run.
	providerClient.CloseIdleConnections()

	temporaryRoot, err := os.MkdirTemp("/tmp", "ai-security-scanner-cloud-")
	if err != nil {
		return fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		return fmt.Errorf("restrict private temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)

	environment := childEnvironment(credentials, selectedProvider, providerTarget, temporaryRoot)
	environment, bridge, err := bridgeProviderTraffic(environment)
	if err != nil {
		return err
	}
	if bridge != nil {
		defer bridge.Close()
	}
	switch *engineID {
	case "cloudsplaining":
		return runCloudsplaining(environment, temporaryRoot, *outputPath)
	case "prowler":
		profile, err := prowlerInvocation(selectedProvider, providerTarget, credentialExpiresAt, environment, *outputPath)
		if err != nil {
			return err
		}
		return runProwler(profile, *outputPath)
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

func awsSTSEndpointForEngine(engineID string) string {
	// Each value is a compile-time endpoint already present in that engine's
	// managed-network closure. The global STS endpoint still signs in us-east-1.
	if engineID == "cloudsplaining" {
		return awsGlobalSTSEndpoint
	}
	return awsRegionalSTSEndpoint
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
	if scope.SchemaVersion != "1" || scope.EngineID != expectedEngine || len(scope.Assets) != 1 {
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
		if asset.Provider == nil || !matchesProvider(*asset.Provider) {
			return nil, errors.New("released cloud engine scope must identify one supported provider")
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

func loadCredentials(path string) (map[string]string, provider, time.Time, error) {
	bytes, err := readBoundedRegularFile(path, maxCredentialSize)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("read protected credential channel: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(bytes)))
	decoder.DisallowUnknownFields()
	var envelope credentialEnvelope
	if err := decoder.Decode(&envelope); err != nil || requireJSONEOF(decoder) != nil {
		return nil, "", time.Time{}, errors.New("credential channel is malformed")
	}
	if envelope.SchemaVersion != "1.0.0" || len(envelope.Credentials) == 0 || len(envelope.Credentials) > 3 {
		return nil, "", time.Time{}, errors.New("credential channel version or entry count is invalid")
	}
	values := make(map[string]string, len(envelope.Credentials))
	minimumExpiry := time.Time{}
	now := time.Now().UTC()
	for _, credential := range envelope.Credentials {
		if !allowedCredentialKey(credential.Key) || !safeSecret(credential.Value, 64*1024) {
			return nil, "", time.Time{}, errors.New("credential channel contains an unauthorized entry")
		}
		if credential.Source != "ephemeral_scan_role" && credential.Source != "external_read_only_grant" {
			return nil, "", time.Time{}, errors.New("credential source is not a scanner-only source")
		}
		if err := validateCredentialLifetime(credential.ExpiresAt, now); err != nil {
			return nil, "", time.Time{}, err
		}
		if _, exists := values[credential.Key]; exists {
			return nil, "", time.Time{}, errors.New("credential channel contains a duplicate key")
		}
		values[credential.Key] = credential.Value
		if minimumExpiry.IsZero() || credential.ExpiresAt.Before(minimumExpiry) {
			minimumExpiry = credential.ExpiresAt.UTC()
		}
	}
	selected, err := providerFromCredentialKeys(values)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return values, selected, minimumExpiry, nil
}

func matchesProvider(value string) bool {
	return value == string(providerAWS) || value == string(providerAzure) || value == string(providerGCP)
}

func validateCredentialLifetime(expiresAt, now time.Time) error {
	if !expiresAt.After(now.Add(minimumCredentialTTL)) || expiresAt.After(now.Add(time.Hour)) {
		return errors.New("credential lifetime is not within the scanner-only five-to-sixty-minute window")
	}
	return nil
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
	if engineID != "prowler" && selected != providerAWS {
		return fmt.Errorf("engine %s has no released %s token profile", engineID, selected)
	}
	if engineID == "prowler" && selected != providerAWS && selected != providerAzure && selected != providerGCP {
		return errors.New("Prowler credential provider is not released")
	}
	for _, asset := range scope.Assets {
		if asset.Provider == nil || *asset.Provider != string(selected) {
			return errors.New("credential provider does not match immutable asset scope")
		}
	}
	return nil
}

func expectedProviderTarget(scope *scopeDocument, selected provider) (string, error) {
	if len(scope.Assets) != 1 {
		return "", errors.New("provider execution must contain exactly one asset")
	}
	asset := scope.Assets[0]
	expectedKind := ""
	expectedNamespace := ""
	switch selected {
	case providerAWS:
		expectedKind, expectedNamespace = "cloud_account", "aws_account_id"
	case providerAzure:
		expectedKind, expectedNamespace = "subscription", "azure_subscription_id"
	case providerGCP:
		expectedKind, expectedNamespace = "project", "gcp_project_id"
	default:
		return "", errors.New("provider execution target is unsupported")
	}
	if asset.Kind != expectedKind || asset.Provider == nil || *asset.Provider != string(selected) {
		return "", errors.New("provider execution scope has the wrong asset kind or provider")
	}
	target := ""
	for _, identifier := range asset.Identifiers {
		if identifier.Namespace != expectedNamespace {
			continue
		}
		if target != "" {
			return "", errors.New("provider execution scope contains more than one native identifier")
		}
		target = identifier.Value
	}
	valid := false
	switch selected {
	case providerAWS:
		valid = validAWSAccountID(target)
	case providerAzure:
		valid = validCanonicalUUID(target)
	case providerGCP:
		valid = validGCPProjectID(target)
	}
	if !valid {
		return "", errors.New("provider execution scope has no valid native identifier")
	}
	return target, nil
}

func expectedAWSAccountID(scope *scopeDocument) (string, error) {
	return expectedProviderTarget(scope, providerAWS)
}

func validAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validGCPProjectID(value string) bool {
	if len(value) < 6 || len(value) > 30 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func verifyAWSCallerIdentity(client httpDoer, endpoint string, credentials map[string]string, expectedAccountID string, now time.Time) error {
	if client == nil {
		return errors.New("AWS STS identity verifier is unavailable")
	}
	if len(expectedAccountID) != 12 {
		return errors.New("AWS STS expected account is invalid")
	}
	accessKeyID := credentials["AWS_ACCESS_KEY_ID"]
	secretAccessKey := credentials["AWS_SECRET_ACCESS_KEY"]
	sessionToken := credentials["AWS_SESSION_TOKEN"]
	if accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
		return errors.New("AWS STS identity verifier lacks the complete credential closure")
	}

	const contentType = "application/x-www-form-urlencoded; charset=utf-8"
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil || request.URL.Path != "/" || request.URL.RawQuery != "" || request.URL.User != nil || request.URL.Fragment != "" {
		return errors.New("AWS STS identity endpoint is invalid")
	}
	host := request.URL.Host
	if host == "" {
		return errors.New("AWS STS identity endpoint has no host")
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	canonicalHeaders := fmt.Sprintf(
		"content-type:%s\nhost:%s\nx-amz-date:%s\nx-amz-security-token:%s\n",
		contentType, host, amzDate, sessionToken,
	)
	const signedHeaders = "content-type;host;x-amz-date;x-amz-security-token"
	payloadHash := sha256Hex(body)
	canonicalRequest := fmt.Sprintf(
		"POST\n/\n\n%s\n%s\n%s",
		canonicalHeaders, signedHeaders, payloadHash,
	)
	credentialScope := fmt.Sprintf("%s/%s/sts/aws4_request", date, awsSTSRegion)
	stringToSign := fmt.Sprintf(
		"AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate, credentialScope, sha256Hex([]byte(canonicalRequest)),
	)
	dateKey := hmacSHA256([]byte("AWS4"+secretAccessKey), []byte(date))
	regionKey := hmacSHA256(dateKey, []byte(awsSTSRegion))
	serviceKey := hmacSHA256(regionKey, []byte("sts"))
	signingKey := hmacSHA256(serviceKey, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	authorization := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credentialScope, signedHeaders, signature,
	)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Security-Token", sessionToken)
	request.Header.Set("Authorization", authorization)

	response, err := client.Do(request)
	if err != nil {
		return errors.New("AWS STS caller identity verification failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("AWS STS caller identity verification returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxProviderResponseSize {
		return errors.New("AWS STS caller identity response exceeds its bound")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponseSize+1))
	if err != nil || len(payload) > maxProviderResponseSize {
		return errors.New("AWS STS caller identity response is unreadable or oversized")
	}
	accountID, err := accountIDFromSTSXML(payload)
	if err != nil {
		return err
	}
	if accountID != expectedAccountID {
		return errors.New("AWS STS caller account does not match the immutable execution scope")
	}
	return nil
}

func accountIDFromSTSXML(payload []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	seenResponse := false
	accounts := make([]string, 0, 1)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("AWS STS caller identity response is malformed")
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "GetCallerIdentityResponse":
			seenResponse = true
		case "Account":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", errors.New("AWS STS caller identity account is malformed")
			}
			accounts = append(accounts, strings.TrimSpace(value))
		}
	}
	if !seenResponse || len(accounts) != 1 || len(accounts[0]) != 12 {
		return "", errors.New("AWS STS caller identity response has no unique account")
	}
	for _, character := range accounts[0] {
		if character < '0' || character > '9' {
			return "", errors.New("AWS STS caller identity response has an invalid account")
		}
	}
	return accounts[0], nil
}

func verifyAzureSubscription(client httpDoer, root, accessToken, expectedSubscriptionID string) error {
	if client == nil || !validCanonicalUUID(expectedSubscriptionID) || !safeText(accessToken, 64*1024) {
		return errors.New("Azure subscription verifier lacks an exact target or token")
	}
	endpoint := strings.TrimSuffix(root, "/") + "/subscriptions/" + expectedSubscriptionID + "?api-version=2022-12-01"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil || request.URL.User != nil || request.URL.Fragment != "" {
		return errors.New("Azure subscription identity endpoint is invalid")
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	payload, err := performProviderRequest(client, request, "Azure subscription identity")
	if err != nil {
		return err
	}
	object, err := uniqueJSONObject(payload)
	if err != nil {
		return errors.New("Azure subscription identity response is malformed")
	}
	var actual string
	if raw, exists := object["subscriptionId"]; !exists || json.Unmarshal(raw, &actual) != nil || actual != expectedSubscriptionID {
		return errors.New("Azure subscription identity does not match the immutable execution scope")
	}
	var state string
	if raw, exists := object["state"]; !exists || json.Unmarshal(raw, &state) != nil || state != "Enabled" {
		return errors.New("Azure subscription identity is not enabled")
	}
	return nil
}

func verifyGCPProject(client httpDoer, root, accessToken, expectedProjectID string) error {
	if client == nil || !validGCPProjectID(expectedProjectID) || !safeText(accessToken, 64*1024) {
		return errors.New("GCP project verifier lacks an exact target or token")
	}
	base := strings.TrimSuffix(root, "/")
	requiredPermissions := []string{
		"resourcemanager.projects.get",
		"resourcemanager.projects.getIamPolicy",
	}
	prohibitedPermissions := []string{
		"resourcemanager.projects.setIamPolicy",
		"resourcemanager.projects.delete",
		"iam.serviceAccounts.create",
		"iam.serviceAccountKeys.create",
	}
	requestedPermissions := append(append([]string{}, requiredPermissions...), prohibitedPermissions...)
	permissionBody, err := json.Marshal(struct {
		Permissions []string `json:"permissions"`
	}{Permissions: requestedPermissions})
	if err != nil {
		return errors.New("GCP project permission request is invalid")
	}
	permissionRequest, err := http.NewRequest(
		http.MethodPost,
		base+"/v3/projects/"+expectedProjectID+":testIamPermissions",
		bytes.NewReader(permissionBody),
	)
	if err != nil || permissionRequest.URL.User != nil || permissionRequest.URL.Fragment != "" {
		return errors.New("GCP project permission endpoint is invalid")
	}
	permissionRequest.Header.Set("Authorization", "Bearer "+accessToken)
	permissionRequest.Header.Set("Accept", "application/json")
	permissionRequest.Header.Set("Content-Type", "application/json")
	permissionPayload, err := performProviderRequest(client, permissionRequest, "GCP project permission")
	if err != nil {
		return err
	}
	permissionObject, err := uniqueJSONObject(permissionPayload)
	if err != nil {
		return errors.New("GCP project permission response is malformed")
	}
	var grantedPermissions []string
	if raw, exists := permissionObject["permissions"]; exists && json.Unmarshal(raw, &grantedPermissions) != nil {
		return errors.New("GCP project permission response has a malformed permissions array")
	}
	requested := make(map[string]struct{}, len(requestedPermissions))
	for _, permission := range requestedPermissions {
		requested[permission] = struct{}{}
	}
	granted := make(map[string]struct{}, len(grantedPermissions))
	for _, permission := range grantedPermissions {
		if _, exists := requested[permission]; !exists {
			return errors.New("GCP project permission response contains an unexpected permission")
		}
		if _, exists := granted[permission]; exists {
			return errors.New("GCP project permission response contains a duplicate permission")
		}
		granted[permission] = struct{}{}
	}
	for _, permission := range requiredPermissions {
		if _, exists := granted[permission]; !exists {
			return fmt.Errorf("GCP project credential is missing required permission %s", permission)
		}
	}
	for _, permission := range prohibitedPermissions {
		if _, exists := granted[permission]; exists {
			return fmt.Errorf("GCP project credential permits prohibited mutation %s", permission)
		}
	}

	projectRequest, err := http.NewRequest(http.MethodGet, base+"/v3/projects/"+expectedProjectID, nil)
	if err != nil || projectRequest.URL.User != nil || projectRequest.URL.Fragment != "" {
		return errors.New("GCP project identity endpoint is invalid")
	}
	projectRequest.Header.Set("Authorization", "Bearer "+accessToken)
	projectRequest.Header.Set("Accept", "application/json")
	projectPayload, err := performProviderRequest(client, projectRequest, "GCP project identity")
	if err != nil {
		return err
	}
	project, err := uniqueJSONObject(projectPayload)
	if err != nil {
		return errors.New("GCP project identity response is malformed")
	}
	var actualProjectID, state string
	if raw, exists := project["projectId"]; !exists || json.Unmarshal(raw, &actualProjectID) != nil || actualProjectID != expectedProjectID {
		return errors.New("GCP project identity does not match the immutable execution scope")
	}
	if raw, exists := project["state"]; !exists || json.Unmarshal(raw, &state) != nil || state != "ACTIVE" {
		return errors.New("GCP project identity is not active")
	}

	policyBody := []byte(`{"options":{"requestedPolicyVersion":3}}`)
	policyRequest, err := http.NewRequest(
		http.MethodPost,
		base+"/v1/projects/"+expectedProjectID+":getIamPolicy",
		bytes.NewReader(policyBody),
	)
	if err != nil || policyRequest.URL.User != nil || policyRequest.URL.Fragment != "" {
		return errors.New("GCP IAM policy endpoint is invalid")
	}
	policyRequest.Header.Set("Authorization", "Bearer "+accessToken)
	policyRequest.Header.Set("Accept", "application/json")
	policyRequest.Header.Set("Content-Type", "application/json")
	policyPayload, err := performProviderRequest(client, policyRequest, "GCP IAM policy")
	if err != nil {
		return err
	}
	policy, err := uniqueJSONObject(policyPayload)
	if err != nil {
		return errors.New("GCP IAM policy response is malformed")
	}
	var bindings []json.RawMessage
	if raw, exists := policy["bindings"]; !exists || json.Unmarshal(raw, &bindings) != nil {
		return errors.New("GCP IAM policy response has no bounded bindings array")
	}
	return nil
}

func performProviderRequest(client httpDoer, request *http.Request, label string) ([]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s verification failed", label)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s verification returned HTTP %d", label, response.StatusCode)
	}
	if response.ContentLength > maxProviderResponseSize {
		return nil, fmt.Errorf("%s response exceeds its bound", label)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponseSize+1))
	if err != nil || len(payload) > maxProviderResponseSize {
		return nil, fmt.Errorf("%s response is unreadable or oversized", label)
	}
	return payload, nil
}

func uniqueJSONObject(payload []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("JSON value is not an object")
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("JSON object key is malformed")
		}
		if _, exists := object[key]; exists {
			return nil, errors.New("JSON object contains a duplicate key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("JSON object value is malformed")
		}
		object[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || requireJSONEOF(decoder) != nil {
		return nil, errors.New("JSON object has trailing or malformed data")
	}
	return object, nil
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func hmacSHA256(key, value []byte) []byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(value)
	return digest.Sum(nil)
}

func childEnvironment(credentials map[string]string, selected provider, providerTarget, temporaryRoot string) []string {
	values := make(map[string]string)
	for _, key := range safeEnvironmentKeys {
		if value, exists := os.LookupEnv(key); exists {
			values[key] = value
		}
	}
	values["HOME"] = temporaryRoot
	values["USER"] = "scanner"
	values["XDG_CACHE_HOME"] = filepath.Join(temporaryRoot, "cache")
	switch selected {
	case providerAWS:
		for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
			values[key] = credentials[key]
		}
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
	case providerAzure:
		values["AZURE_ACCESS_TOKEN"] = credentials["AZURE_ACCESS_TOKEN"]
	case providerGCP:
		values["CLOUDSDK_AUTH_ACCESS_TOKEN"] = credentials["GOOGLE_OAUTH_ACCESS_TOKEN"]
		values["GOOGLE_CLOUD_PROJECT"] = providerTarget
		values["GOOGLE_API_USE_MTLS_ENDPOINT"] = "never"
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
	return environment
}

// The managed gateway speaks only SOCKS5. The Python SDKs in Prowler,
// ScoutSuite and Cloudsplaining cannot use a SOCKS proxy, and CloudQuery's
// Go 1.19 build does not accept the socks5h scheme, so for the length of the
// engine process the launcher runs a loopback HTTP proxy for every engine and
// opens each tunnel through the gateway. The gateway still decides which
// provider hosts a tunnel may reach.
const (
	managedGatewayPort = "1080"
	// The gateway admits ten provider tunnels at once and 25 new ones a second
	// (ManagedEgressPolicy::from_provider_service_plan), and refuses a tunnel
	// it cannot admit within its connect timeout. Staying under both keeps
	// that wait here.
	providerTunnelLimit      = 8
	providerTunnelsPerSecond = 20
	// An idle keep-alive tunnel still holds a gateway slot. A tunnel whose last
	// bytes were the provider's answer is closed after a short pause, and the
	// engine reconnects on its next request. A tunnel still waiting for an
	// answer gets longer than the SDKs' own read timeouts.
	providerTunnelIdle       = 5 * time.Second
	providerTunnelAwaiting   = 120 * time.Second
	providerTunnelHandshake  = 60 * time.Second
	maxProxyRequestHeaderLen = 16 * 1024
)

var bridgedProxyKeys = []string{"ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"}

var errGatewayRefusedTunnel = errors.New("managed SOCKS gateway refused the tunnel")

func bridgeProviderTraffic(environment []string) ([]string, *providerBridge, error) {
	gateway, present := "", false
	for _, entry := range environment {
		if value, found := strings.CutPrefix(entry, "AI_SECURITY_SCANNER_PROXY="); found {
			gateway, present = value, true
		}
	}
	if !present {
		return environment, nil, nil
	}
	address, err := managedGatewayAddress(gateway)
	if err != nil {
		return nil, nil, err
	}
	bridge, err := startProviderBridge(address, providerTunnelLimit, providerTunnelsPerSecond, providerTunnelIdle, providerTunnelAwaiting)
	if err != nil {
		return nil, nil, err
	}
	proxy := "http://" + bridge.listener.Addr().String()
	for _, key := range bridgedProxyKeys {
		environment = replaceEnvironmentValue(environment, key, proxy)
	}
	return environment, bridge, nil
}

func managedGatewayAddress(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5h" || parsed.User != nil || parsed.Port() != managedGatewayPort ||
		net.ParseIP(parsed.Hostname()) == nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("managed SOCKS gateway endpoint is absent or malformed")
	}
	return net.JoinHostPort(parsed.Hostname(), parsed.Port()), nil
}

type providerBridge struct {
	listener *net.TCPListener
	gateway  string
	idle     time.Duration
	awaiting time.Duration
	slots    chan struct{}
	pace     *time.Ticker
	stop     chan struct{}
	stopOnce sync.Once
	mutex    sync.Mutex
	open     map[net.Conn]struct{}
	workers  sync.WaitGroup
}

func startProviderBridge(gateway string, limit, perSecond int, idle, awaiting time.Duration) (*providerBridge, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, errors.New("open the loopback provider proxy")
	}
	bridge := &providerBridge{
		listener: listener,
		gateway:  gateway,
		idle:     idle,
		awaiting: awaiting,
		slots:    make(chan struct{}, limit),
		pace:     time.NewTicker(time.Second / time.Duration(perSecond)),
		stop:     make(chan struct{}),
		open:     make(map[net.Conn]struct{}),
	}
	bridge.workers.Add(1)
	go bridge.serve()
	return bridge, nil
}

func (bridge *providerBridge) Close() {
	bridge.stopOnce.Do(func() {
		close(bridge.stop)
		_ = bridge.listener.Close()
		bridge.pace.Stop()
		bridge.mutex.Lock()
		for connection := range bridge.open {
			_ = connection.Close()
		}
		bridge.open = nil
		bridge.mutex.Unlock()
	})
	bridge.workers.Wait()
}

func (bridge *providerBridge) serve() {
	defer bridge.workers.Done()
	for {
		client, err := bridge.listener.Accept()
		if err != nil {
			select {
			case <-bridge.stop:
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}
		if !bridge.track(client) {
			_ = client.Close()
			return
		}
		bridge.workers.Add(1)
		go func() {
			defer bridge.workers.Done()
			defer bridge.release(client)
			bridge.handle(client)
		}()
	}
}

func (bridge *providerBridge) track(connection net.Conn) bool {
	bridge.mutex.Lock()
	defer bridge.mutex.Unlock()
	if bridge.open == nil {
		return false
	}
	bridge.open[connection] = struct{}{}
	return true
}

func (bridge *providerBridge) release(connection net.Conn) {
	_ = connection.Close()
	bridge.mutex.Lock()
	defer bridge.mutex.Unlock()
	if bridge.open != nil {
		delete(bridge.open, connection)
	}
}

func (bridge *providerBridge) handle(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(providerTunnelHandshake))
	reader := bufio.NewReader(&io.LimitedReader{R: client, N: maxProxyRequestHeaderLen})
	request, err := http.ReadRequest(reader)
	if err != nil {
		writeProxyStatus(client, http.StatusBadRequest)
		return
	}
	if request.Method != http.MethodConnect {
		writeProxyStatus(client, http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(request.Host)
	if err != nil || port != "443" || !providerHostname(host) {
		writeProxyStatus(client, http.StatusForbidden)
		return
	}
	upstream, status := bridge.tunnel(host)
	if upstream == nil {
		writeProxyStatus(client, status)
		return
	}
	defer func() {
		bridge.release(upstream)
		<-bridge.slots
	}()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	if buffered := reader.Buffered(); buffered > 0 {
		early, _ := reader.Peek(buffered)
		if _, err := upstream.Write(early); err != nil {
			return
		}
	}
	bridge.relay(client, upstream)
}

// tunnel waits for a gateway slot and the pace, then opens one SOCKS CONNECT.
// On success the caller owns the slot until the tunnel closes.
func (bridge *providerBridge) tunnel(host string) (net.Conn, int) {
	select {
	case bridge.slots <- struct{}{}:
	case <-bridge.stop:
		return nil, http.StatusServiceUnavailable
	}
	select {
	case <-bridge.pace.C:
	case <-bridge.stop:
		<-bridge.slots
		return nil, http.StatusServiceUnavailable
	}
	upstream, err := dialGatewayTunnel(bridge.gateway, host, 443)
	if err == nil && bridge.track(upstream) {
		return upstream, http.StatusOK
	}
	if upstream != nil {
		_ = upstream.Close()
	}
	<-bridge.slots
	if errors.Is(err, errGatewayRefusedTunnel) {
		return nil, http.StatusForbidden
	}
	return nil, http.StatusBadGateway
}

// relay copies both ways until either side ends, the bridge stops, or the
// tunnel sits idle. A tunnel opens for a request, so it counts as waiting for
// an answer until the provider sends one.
func (bridge *providerBridge) relay(client, upstream net.Conn) {
	var lastActivity atomic.Int64
	var awaiting atomic.Bool
	lastActivity.Store(time.Now().UnixNano())
	awaiting.Store(true)
	finished := make(chan struct{}, 2)
	pipe := func(destination, source net.Conn, request bool) {
		buffer := make([]byte, 32*1024)
		for {
			count, err := source.Read(buffer)
			if count > 0 {
				lastActivity.Store(time.Now().UnixNano())
				awaiting.Store(request)
				if _, writeErr := destination.Write(buffer[:count]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		finished <- struct{}{}
	}
	go pipe(upstream, client, true)
	go pipe(client, upstream, false)
	check := time.NewTicker(bridge.idle / 4)
	defer check.Stop()
	ended := 0
wait:
	for {
		select {
		case <-finished:
			ended++
			break wait
		case <-check.C:
			limit := bridge.idle
			if awaiting.Load() {
				limit = bridge.awaiting
			}
			if time.Since(time.Unix(0, lastActivity.Load())) >= limit {
				break wait
			}
		case <-bridge.stop:
			break wait
		}
	}
	_ = client.Close()
	_ = upstream.Close()
	for ; ended < 2; ended++ {
		<-finished
	}
}

func dialGatewayTunnel(gateway, host string, port uint16) (net.Conn, error) {
	connection, err := net.DialTimeout("tcp", gateway, 30*time.Second)
	if err != nil {
		return nil, errors.New("connect to the managed SOCKS gateway")
	}
	fail := func(cause error) (net.Conn, error) {
		_ = connection.Close()
		return nil, cause
	}
	// The gateway admits at most ten tunnels and makes the eleventh wait before
	// it answers the greeting, so the handshake allows for that wait.
	if err := connection.SetDeadline(time.Now().Add(providerTunnelHandshake)); err != nil {
		return fail(errors.New("set the managed SOCKS handshake deadline"))
	}
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return fail(errors.New("write the managed SOCKS greeting"))
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil || method[0] != 5 || method[1] != 0 {
		return fail(errors.New("managed SOCKS gateway rejected the greeting"))
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := connection.Write(request); err != nil {
		return fail(errors.New("write the managed SOCKS CONNECT"))
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[0] != 5 || reply[2] != 0 {
		return fail(errors.New("read the managed SOCKS CONNECT reply"))
	}
	if reply[1] != 0 {
		return fail(errGatewayRefusedTunnel)
	}
	var bound int
	switch reply[3] {
	case 1:
		bound = 4
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil || length[0] == 0 {
			return fail(errors.New("managed SOCKS gateway returned a malformed host name"))
		}
		bound = int(length[0])
	case 4:
		bound = 16
	default:
		return fail(errors.New("managed SOCKS gateway returned an unknown address type"))
	}
	if _, err := io.ReadFull(connection, make([]byte, bound+2)); err != nil {
		return fail(errors.New("read the managed SOCKS bound address"))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fail(errors.New("clear the managed SOCKS handshake deadline"))
	}
	return connection, nil
}

// providerHostname accepts a DNS host name with at least two labels. Provider
// endpoints are always names; the gateway's allowlist holds names, not IPs.
func providerHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func writeProxyStatus(client net.Conn, status int) {
	_, _ = fmt.Fprintf(client, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}

func prowlerInvocation(selected provider, providerTarget string, credentialExpiresAt time.Time, environment []string, output string) (invocation, error) {
	if output != "/output" {
		return invocation{}, errors.New("Prowler output path is outside the managed mount")
	}
	common := []string{
		"--output-formats", "json-ocsf", "--output-filename", "prowler",
		"--output-directory", output, "--ignore-exit-code-3", "--no-banner",
		"--no-color",
	}
	args := make([]string, 0, 32)
	switch selected {
	case providerAWS:
		if !validAWSAccountID(providerTarget) {
			return invocation{}, errors.New("Prowler AWS target is invalid")
		}
		args = append(args, "aws", "--service", "iam", "--region", "us-east-1")
	case providerAzure:
		now := time.Now().UTC()
		if !validCanonicalUUID(providerTarget) || !credentialExpiresAt.After(now.Add(minimumCredentialTTL)) || credentialExpiresAt.After(now.Add(time.Hour)) {
			return invocation{}, errors.New("Prowler Azure target or token expiry is invalid")
		}
		args = append(args,
			"azure", "--access-token-auth", "--access-token-expires-at", fmt.Sprintf("%d", credentialExpiresAt.Unix()),
			"--subscription-ids", providerTarget, "--service", "iam",
		)
	case providerGCP:
		if !validGCPProjectID(providerTarget) {
			return invocation{}, errors.New("Prowler GCP target is invalid")
		}
		args = append(args,
			"gcp", "--project-ids", providerTarget,
			"--checks", "iam_audit_logs_enabled", "iam_no_service_roles_at_project_level",
			"iam_role_kms_enforce_separation_of_duties", "iam_role_sa_enforce_separation_of_duties",
			"--skip-api-check", "--gcp-retries-max-attempts", "2",
		)
	default:
		return invocation{}, errors.New("Prowler provider profile is unsupported")
	}
	args = append(args, common...)
	if selected == providerAWS {
		args = append(args, "--skip-sh-update")
	}
	return invocation{
		Program: "/home/prowler/.venv/bin/prowler",
		Args:    args,
		Env:     environment,
	}, nil
}

func runProwler(profile invocation, output string) error {
	destination := filepath.Join(output, "prowler.ocsf.json")
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("normalized Prowler output already exists")
	}
	if err := runCommand(profile); err != nil {
		return err
	}
	if err := validateProwlerOutput(destination); err != nil {
		return fmt.Errorf("validate Prowler OCSF output: %w", err)
	}
	return nil
}

func validateProwlerOutput(path string) error {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("Prowler OCSF output cannot be opened without following links")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return errors.New("Prowler OCSF output descriptor is invalid")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxOutputFileSize {
		return errors.New("Prowler OCSF output is not a bounded regular file")
	}
	limited := &io.LimitedReader{R: file, N: maxOutputFileSize + 1}
	reader := bufio.NewReaderSize(limited, 64*1024)
	if err := validateProwlerJSONArray(reader); err != nil {
		return err
	}
	if limited.N == 0 {
		return errors.New("Prowler OCSF output grew beyond its size bound")
	}
	return nil
}

func validateProwlerJSONArray(reader *bufio.Reader) error {
	opening, err := readNextNonWhitespace(reader)
	if err != nil || opening != '[' {
		return errors.New("Prowler OCSF output must be one JSON array")
	}
	records := 0
	next, err := readNextNonWhitespace(reader)
	if err != nil {
		return errors.New("Prowler OCSF output is truncated")
	}
	if next == ']' {
		return requireWhitespaceEOF(reader)
	}
	for {
		if next != '{' {
			return errors.New("Prowler OCSF array contains a non-object record")
		}
		record, err := readJSONObjectRecord(reader, next)
		if err != nil {
			return err
		}
		if !json.Valid(record) {
			return errors.New("Prowler OCSF array contains malformed JSON")
		}
		records++
		if records > maxJSONRecords {
			return errors.New("Prowler OCSF output exceeds its record bound")
		}
		separator, err := readNextNonWhitespace(reader)
		if err != nil {
			return errors.New("Prowler OCSF output is truncated")
		}
		switch separator {
		case ']':
			return requireWhitespaceEOF(reader)
		case ',':
			next, err = readNextNonWhitespace(reader)
			if err != nil {
				return errors.New("Prowler OCSF output is truncated")
			}
		default:
			return errors.New("Prowler OCSF array has an invalid separator")
		}
	}
}

func readJSONObjectRecord(reader *bufio.Reader, opening byte) ([]byte, error) {
	record := make([]byte, 1, 4096)
	record[0] = opening
	depth := 1
	inString := false
	escaped := false
	for depth > 0 {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, errors.New("Prowler OCSF record is truncated")
		}
		if len(record) >= maxJSONRecordSize {
			return nil, errors.New("Prowler OCSF record exceeds its size bound")
		}
		record = append(record, value)
		if inString {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == '"' {
				inString = false
			}
			continue
		}
		switch value {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth < 0 {
				return nil, errors.New("Prowler OCSF record has invalid nesting")
			}
		}
	}
	return record, nil
}

func readNextNonWhitespace(reader *bufio.Reader) (byte, error) {
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if !isJSONWhitespace(value) {
			return value, nil
		}
	}
}

func requireWhitespaceEOF(reader *bufio.Reader) error {
	for {
		value, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil || !isJSONWhitespace(value) {
			return errors.New("Prowler OCSF output has trailing data")
		}
	}
}

func isJSONWhitespace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\r' || value == '\t'
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
	if err := writeExclusive(queryPath, []byte(steampipeIAMUserInventoryQuery), 0o600); err != nil {
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

// Steampipe is an upstream SQL inventory engine. Keep this query to identity
// fields exposed directly by aws_iam_user; policy decisions such as whether an
// IAM user's MFA state is a vulnerability belong to an applicable security
// checker, not to this inventory path.
const steampipeIAMUserInventoryQuery = `select
  'aws_iam_user' as resource_type,
  account_id,
  arn,
  user_id,
  name
from aws_iam_user;
`

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

func safeSecret(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
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

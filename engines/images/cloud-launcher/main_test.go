package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (function httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProviderRequiresExactCredentialClosure(t *testing.T) {
	aws := map[string]string{
		"AWS_ACCESS_KEY_ID":     "id",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "token",
	}
	if selected, err := providerFromCredentialKeys(aws); err != nil || selected != providerAWS {
		t.Fatalf("AWS credential closure rejected: %v", err)
	}
	aws["AZURE_ACCESS_TOKEN"] = "mixed"
	if _, err := providerFromCredentialKeys(aws); err == nil {
		t.Fatal("mixed provider credentials were accepted")
	}
	for name, test := range map[string]struct {
		credentials map[string]string
		provider    provider
	}{
		"azure": {map[string]string{"AZURE_ACCESS_TOKEN": "token"}, providerAzure},
		"gcp":   {map[string]string{"GOOGLE_OAUTH_ACCESS_TOKEN": "token"}, providerGCP},
	} {
		t.Run(name, func(t *testing.T) {
			selected, err := providerFromCredentialKeys(test.credentials)
			if err != nil || selected != test.provider {
				t.Fatalf("exact provider closure rejected: %q %v", selected, err)
			}
		})
	}
}

func TestCredentialLifetimeIsShortLivedBeforeProviderRequests(t *testing.T) {
	now := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	if err := validateCredentialLifetime(now.Add(30*time.Minute), now); err != nil {
		t.Fatalf("short-lived credential rejected: %v", err)
	}
	for name, expiry := range map[string]time.Time{
		"too-short": now.Add(minimumCredentialTTL),
		"too-long":  now.Add(time.Hour + time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCredentialLifetime(expiry, now); err == nil {
				t.Fatal("out-of-contract credential lifetime was accepted")
			}
		})
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "credentials.json")
	envelope := credentialEnvelope{
		SchemaVersion: "1.0.0",
		Credentials: []credentialEntry{
			{Key: "AWS_ACCESS_KEY_ID", Value: "ASIAFIXTURE", ExpiresAt: time.Now().UTC().Add(30 * time.Minute), Source: "ephemeral_scan_role"},
			{Key: "AWS_SECRET_ACCESS_KEY", Value: "fixture-secret", ExpiresAt: time.Now().UTC().Add(30 * time.Minute), Source: "ephemeral_scan_role"},
			{Key: "AWS_SESSION_TOKEN", Value: "fixture-session", ExpiresAt: time.Now().UTC().Add(time.Hour + time.Minute), Source: "ephemeral_scan_role"},
		},
	}
	bytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadCredentials(path); err == nil {
		t.Fatal("credential envelope with one overlong entry was accepted")
	}
}

func TestCredentialValuesRequirePrintableASCIIWithoutWhitespace(t *testing.T) {
	for _, valid := range []string{"header.payload.signature", "AWS+/session==", "opaque-token_123"} {
		if !safeSecret(valid, 64*1024) {
			t.Fatalf("valid scanner token rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "token with space", "token\nheader", "tökén"} {
		if safeSecret(invalid, 64*1024) {
			t.Fatalf("unsafe scanner token accepted: %q", invalid)
		}
	}
}

func TestScopeRejectsUnknownFieldsAndExpiredGrants(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "scope.json")
	expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	scope := map[string]any{
		"schema_version": "1",
		"engine_id":      "prowler",
		"generated_at":   time.Now().UTC().Format(time.RFC3339Nano),
		"assets": []any{map[string]any{
			"id": "asset", "name": "account", "kind": "cloud_account", "provider": "aws",
			"region": nil, "identifiers": []any{},
			"grants": []any{map[string]any{
				"id": "grant", "permission": "inventory_read", "confirmed_by": "tester",
				"confirmed_at": time.Now().UTC().Format(time.RFC3339Nano), "expires_at": expired,
				"authorization_reference": nil, "external_scope": nil,
			}},
		}},
	}
	bytes, _ := json.Marshal(scope)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := loadScope(path, "prowler")
	if err != nil {
		t.Fatalf("parse scope: %v", err)
	}
	if err := validateScopePermissions(document, "prowler"); err == nil {
		t.Fatal("expired scope grant was accepted")
	}
	scope["unexpected"] = true
	bytes, _ = json.Marshal(scope)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path, "prowler"); err == nil {
		t.Fatal("unknown scope field was accepted")
	}
}

func TestScopeRequiresExactlyOneAWSAccountIdentifier(t *testing.T) {
	providerName := "aws"
	base := scopeAsset{
		ID:       "asset-1",
		Name:     "account",
		Kind:     "cloud_account",
		Provider: &providerName,
		Identifiers: []identifier{
			{Namespace: "aws_account_id", Value: "111122223333"},
		},
	}
	document := &scopeDocument{SchemaVersion: "1", EngineID: "prowler", Assets: []scopeAsset{base}}
	if accountID, err := expectedAWSAccountID(document); err != nil || accountID != "111122223333" {
		t.Fatalf("exact AWS account was rejected: %q %v", accountID, err)
	}

	duplicate := base
	duplicate.Identifiers = append(append([]identifier(nil), base.Identifiers...), identifier{
		Namespace: "aws_account_id",
		Value:     "444455556666",
	})
	for name, assets := range map[string][]scopeAsset{
		"none":       nil,
		"two-assets": {base, base},
		"duplicate":  {duplicate},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := expectedAWSAccountID(&scopeDocument{Assets: assets}); err == nil {
				t.Fatal("ambiguous AWS scope was accepted")
			}
		})
	}
}

func TestProviderTargetsBindExactAssetKindsAndNativeIdentifiers(t *testing.T) {
	azure := "azure"
	gcp := "gcp"
	for name, test := range map[string]struct {
		selected provider
		asset    scopeAsset
		expected string
	}{
		"azure": {
			selected: providerAzure,
			asset: scopeAsset{Kind: "subscription", Provider: &azure, Identifiers: []identifier{
				{Namespace: "azure_subscription_id", Value: "11111111-2222-3333-4444-555555555555"},
			}},
			expected: "11111111-2222-3333-4444-555555555555",
		},
		"gcp": {
			selected: providerGCP,
			asset: scopeAsset{Kind: "project", Provider: &gcp, Identifiers: []identifier{
				{Namespace: "gcp_project_id", Value: "audit-project-123"},
			}},
			expected: "audit-project-123",
		},
	} {
		t.Run(name, func(t *testing.T) {
			document := &scopeDocument{Assets: []scopeAsset{test.asset}}
			target, err := expectedProviderTarget(document, test.selected)
			if err != nil || target != test.expected {
				t.Fatalf("exact provider target rejected: %q %v", target, err)
			}
			if _, err := expectedProviderTarget(document, providerAWS); err == nil {
				t.Fatal("cross-provider asset/credential pairing was accepted")
			}
		})
	}

	if validCanonicalUUID("11111111-2222-3333-4444-55555555555A") {
		t.Fatal("non-canonical Azure subscription ID was accepted")
	}
	if validGCPProjectID("-invalid-project") || validGCPProjectID("invalid-project-") {
		t.Fatal("invalid GCP project ID was accepted")
	}
}

func TestAWSCallerIdentityIsVerifiedBeforeDispatch(t *testing.T) {
	credentials := map[string]string{
		"AWS_ACCESS_KEY_ID":     "ASIAFIXTURE",
		"AWS_SECRET_ACCESS_KEY": "fixture-secret",
		"AWS_SESSION_TOKEN":     "fixture-session",
	}
	now := time.Date(2026, time.August, 24, 12, 34, 56, 0, time.UTC)
	client := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/" {
			t.Errorf("unexpected STS request %s %s", request.Method, request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
			t.Errorf("unexpected STS request body %q: %v", body, err)
		}
		const expectedAuthorization = "AWS4-HMAC-SHA256 Credential=ASIAFIXTURE/20260824/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=d0cfb7c30a8eded851827fefd7a5b30dad8c121fc86ed16d75965ecaf16d8e51"
		if request.Header.Get("X-Amz-Date") != "20260824T123456Z" ||
			request.Header.Get("X-Amz-Security-Token") != "fixture-session" ||
			request.Header.Get("Authorization") != expectedAuthorization {
			t.Error("STS request did not carry the fixed signed identity profile")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:assumed-role/security-audit-reader/session</Arn><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`,
			)),
			ContentLength: -1,
		}, nil
	})

	if err := verifyAWSCallerIdentity(client, awsRegionalSTSEndpoint, credentials, "111122223333", now); err != nil {
		t.Fatalf("matching STS caller was rejected: %v", err)
	}
	if err := verifyAWSCallerIdentity(client, awsRegionalSTSEndpoint, credentials, "444455556666", now); err == nil {
		t.Fatal("STS caller from a different account was accepted")
	}
}

func TestAWSIdentityEndpointMatchesEachReleasedNetworkClosure(t *testing.T) {
	for _, engineID := range []string{"cloudquery", "steampipe", "prowler", "scoutsuite"} {
		if endpoint := awsSTSEndpointForEngine(engineID); endpoint != awsRegionalSTSEndpoint {
			t.Fatalf("%s selected unexpected STS endpoint %s", engineID, endpoint)
		}
	}
	if endpoint := awsSTSEndpointForEngine("cloudsplaining"); endpoint != awsGlobalSTSEndpoint {
		t.Fatalf("cloudsplaining selected unexpected STS endpoint %s", endpoint)
	}
}

func TestAWSCallerIdentityRejectsMalformedOrAmbiguousEvidence(t *testing.T) {
	for name, response := range map[string]string{
		"malformed": `<GetCallerIdentityResponse><Account>111122223333`,
		"ambiguous": `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Account>444455556666</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, response)
			}))
			defer server.Close()
			credentials := map[string]string{
				"AWS_ACCESS_KEY_ID":     "ASIAFIXTURE",
				"AWS_SECRET_ACCESS_KEY": "fixture-secret",
				"AWS_SESSION_TOKEN":     "fixture-session",
			}
			if err := verifyAWSCallerIdentity(server.Client(), server.URL+"/", credentials, "111122223333", time.Now().UTC()); err == nil {
				t.Fatal("untrusted STS evidence was accepted")
			}
		})
	}
}

func TestAzureSubscriptionPreflightBindsBearerTokenAndNativeID(t *testing.T) {
	const subscriptionID = "11111111-2222-3333-4444-555555555555"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasPrefix(request.URL.Path, "/subscriptions/") || request.URL.Query().Get("api-version") != "2022-12-01" {
			t.Errorf("unexpected Azure request %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer azure-token" {
			t.Error("Azure bearer token was not passed through the fixed header")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"subscriptionId":"`+subscriptionID+`","state":"Enabled"}`)
	}))
	defer server.Close()
	if err := verifyAzureSubscription(server.Client(), server.URL, "azure-token", subscriptionID); err != nil {
		t.Fatalf("exact Azure subscription was rejected: %v", err)
	}
	if err := verifyAzureSubscription(server.Client(), server.URL, "azure-token", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"); err == nil {
		t.Fatal("different Azure subscription was accepted")
	}
}

func TestAzureSubscriptionPreflightRejectsDisabledSubscription(t *testing.T) {
	const subscriptionID = "11111111-2222-3333-4444-555555555555"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"subscriptionId":"`+subscriptionID+`","state":"Disabled"}`)
	}))
	defer server.Close()
	if err := verifyAzureSubscription(server.Client(), server.URL, "azure-token", subscriptionID); err == nil {
		t.Fatal("disabled Azure subscription was accepted")
	}
}

func TestGCPProjectPreflightPinsPermissionsAndUsesOnlyExactProjectReads(t *testing.T) {
	const projectID = "audit-project-123"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer gcp-token" {
			t.Error("GCP bearer token was not passed through the fixed header")
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v3/projects/"+projectID+":testIamPermissions":
			body, _ := io.ReadAll(request.Body)
			expected := `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy","resourcemanager.projects.setIamPolicy","resourcemanager.projects.delete","iam.serviceAccounts.create","iam.serviceAccountKeys.create"]}`
			if string(body) != expected {
				t.Errorf("unexpected GCP permission body %q", body)
			}
			_, _ = io.WriteString(writer, `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy"]}`)
		case request.Method == http.MethodGet && request.URL.Path == "/v3/projects/"+projectID:
			_, _ = io.WriteString(writer, `{"name":"projects/fixture","projectId":"`+projectID+`","state":"ACTIVE"}`)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/projects/"+projectID+":getIamPolicy":
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"options":{"requestedPolicyVersion":3}}` {
				t.Errorf("unexpected GCP policy body %q", body)
			}
			_, _ = io.WriteString(writer, `{"version":3,"bindings":[]}`)
		default:
			t.Errorf("ambient or unexpected GCP request %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	if err := verifyGCPProject(server.Client(), server.URL, "gcp-token", projectID); err != nil {
		t.Fatalf("exact GCP project was rejected: %v", err)
	}
	if requests != 3 {
		t.Fatalf("expected exactly three bounded GCP preflight calls, got %d", requests)
	}
}

func TestGCPProjectPreflightFailsClosedWhenExactIAMPolicyReadIsDenied(t *testing.T) {
	const projectID = "audit-project-123"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v3/projects/"+projectID+":testIamPermissions":
			_, _ = io.WriteString(writer, `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy"]}`)
		case request.Method == http.MethodGet && request.URL.Path == "/v3/projects/"+projectID:
			_, _ = io.WriteString(writer, `{"name":"projects/987654321","projectId":"`+projectID+`","state":"ACTIVE"}`)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/projects/"+projectID+":getIamPolicy":
			http.Error(writer, "denied", http.StatusForbidden)
		default:
			http.Error(writer, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	err := verifyGCPProject(server.Client(), server.URL, "gcp-token", projectID)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("missing projects.getIamPolicy permission was not rejected: %v", err)
	}
	if requests != 3 {
		t.Fatalf("expected permission, exact identity, then IAM-policy preflight, got %d calls", requests)
	}
}

func TestGCPProjectPreflightFailsClosedOnMissingReadOrGrantedMutation(t *testing.T) {
	const projectID = "audit-project-123"
	for name, permissions := range map[string]string{
		"missing-read":               `{"permissions":["resourcemanager.projects.get"]}`,
		"set-project-policy":         `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy","resourcemanager.projects.setIamPolicy"]}`,
		"delete-project":             `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy","resourcemanager.projects.delete"]}`,
		"create-service-account":     `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy","iam.serviceAccounts.create"]}`,
		"create-service-account-key": `{"permissions":["resourcemanager.projects.get","resourcemanager.projects.getIamPolicy","iam.serviceAccountKeys.create"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests++
				if request.Method != http.MethodPost || request.URL.Path != "/v3/projects/"+projectID+":testIamPermissions" {
					http.Error(writer, "unexpected", http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(writer, permissions)
			}))
			defer server.Close()

			err := verifyGCPProject(server.Client(), server.URL, "gcp-token", projectID)
			if err == nil {
				t.Fatal("unsafe GCP project permission set was accepted")
			}
			if requests != 1 {
				t.Fatalf("unsafe permission set reached live project reads after %d calls", requests)
			}
		})
	}
}

func TestChildEnvironmentDropsAmbientSecrets(t *testing.T) {
	t.Setenv("AWS_PROFILE", "must-not-pass")
	t.Setenv("PROWLER_CLOUD_API_KEY", "must-not-pass")
	t.Setenv("HTTPS_PROXY", "socks5h://gateway:1080")
	environment := childEnvironment(map[string]string{
		"AWS_ACCESS_KEY_ID":     "id",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "token",
	}, providerAWS, "111122223333", "/tmp/private")
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	if strings.Contains(joined, "AWS_PROFILE=") || strings.Contains(joined, "PROWLER_CLOUD_API_KEY=") {
		t.Fatal("ambient secret escaped into child environment")
	}
	if !strings.Contains(joined, "\nHTTPS_PROXY=socks5h://gateway:1080\n") {
		t.Fatal("managed proxy was not preserved")
	}
	if !strings.Contains(joined, "\nAWS_MAX_ATTEMPTS=2\n") ||
		!strings.Contains(joined, "\nAWS_RETRY_MODE=standard\n") {
		t.Fatal("AWS retries are not statically bounded")
	}
}

func TestGCPChildEnvironmentMapsTokenWithoutAmbientCredentialFallback(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/ambient/credentials.json")
	t.Setenv("CLOUDSDK_CONFIG", "/ambient/gcloud")
	environment := childEnvironment(
		map[string]string{"GOOGLE_OAUTH_ACCESS_TOKEN": "gcp-token"},
		providerGCP,
		"audit-project-123",
		"/tmp/private",
	)
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	for _, forbidden := range []string{"GOOGLE_OAUTH_ACCESS_TOKEN=", "GOOGLE_APPLICATION_CREDENTIALS=", "CLOUDSDK_CONFIG="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden GCP credential path escaped: %s", forbidden)
		}
	}
	for _, required := range []string{
		"\nCLOUDSDK_AUTH_ACCESS_TOKEN=gcp-token\n",
		"\nGOOGLE_CLOUD_PROJECT=audit-project-123\n",
		"\nGOOGLE_API_USE_MTLS_ENDPOINT=never\n",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("GCP environment lacks %q", required)
		}
	}
}

func TestProwlerProviderInvocationsAreExactAndNarrow(t *testing.T) {
	expiry := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	for name, test := range map[string]struct {
		selected provider
		target   string
		prefix   []string
	}{
		"aws": {
			selected: providerAWS,
			target:   "111122223333",
			prefix:   []string{"aws", "--service", "iam", "--region", "us-east-1"},
		},
		"azure": {
			selected: providerAzure,
			target:   "11111111-2222-3333-4444-555555555555",
			prefix: []string{
				"azure", "--access-token-auth", "--access-token-expires-at", strconv.FormatInt(expiry.Unix(), 10),
				"--subscription-ids", "11111111-2222-3333-4444-555555555555", "--service", "iam",
			},
		},
		"gcp": {
			selected: providerGCP,
			target:   "audit-project-123",
			prefix: []string{
				"gcp", "--project-ids", "audit-project-123", "--checks",
				"iam_audit_logs_enabled", "iam_no_service_roles_at_project_level",
				"iam_role_kms_enforce_separation_of_duties", "iam_role_sa_enforce_separation_of_duties",
				"--skip-api-check", "--gcp-retries-max-attempts", "2",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile, err := prowlerInvocation(test.selected, test.target, expiry, []string{"HOME=/tmp/private"}, "/output")
			if err != nil {
				t.Fatalf("build Prowler invocation: %v", err)
			}
			common := []string{
				"--output-formats", "json-ocsf", "--output-filename", "prowler", "--output-directory", "/output",
				"--ignore-exit-code-3", "--no-banner", "--no-color",
			}
			expected := append(append([]string(nil), test.prefix...), common...)
			if test.selected == providerAWS {
				expected = append(expected, "--skip-sh-update")
			}
			if strings.Join(profile.Args, "\x00") != strings.Join(expected, "\x00") {
				t.Fatalf("unexpected %s argv: %#v", name, profile.Args)
			}
		})
	}
}

func TestProwlerOutputValidationIsBoundedAndFailClosed(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(valid, []byte(`[{"status_code":"FAIL","finding_info":{"uid":"fixture"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProwlerOutput(valid); err != nil {
		t.Fatalf("valid OCSF array rejected: %v", err)
	}

	for name, payload := range map[string]string{
		"non-array":  `{"status_code":"FAIL"}`,
		"non-object": `["finding"]`,
		"trailing":   `[] {}`,
		"malformed":  `[{"status_code":]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateProwlerOutput(path); err == nil {
				t.Fatal("invalid Prowler output was accepted")
			}
		})
	}

	oversized := filepath.Join(directory, "oversized-record.json")
	payload := `[{"value":"` + strings.Repeat("a", maxJSONRecordSize) + `"}]`
	if err := os.WriteFile(oversized, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProwlerOutput(oversized); err == nil {
		t.Fatal("oversized Prowler record was accepted")
	}

	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if err := validateProwlerOutput(symlink); err == nil {
		t.Fatal("symlinked Prowler output was accepted")
	}
}

func TestRunCommandToFileBoundsAndCleansOutput(t *testing.T) {
	directory := t.TempDir()
	success := filepath.Join(directory, "success.json")
	if err := runCommandToFile(invocation{Program: "/bin/echo", Args: []string{"evidence"}}, success); err != nil {
		t.Fatalf("capture successful output: %v", err)
	}
	content, err := os.ReadFile(success)
	if err != nil || string(content) != "evidence\n" {
		t.Fatalf("unexpected captured output %q: %v", content, err)
	}

	failure := filepath.Join(directory, "failure.json")
	if err := runCommandToFile(invocation{Program: "/bin/false"}, failure); err == nil {
		t.Fatal("failed child process was accepted")
	}
	if _, err := os.Lstat(failure); !os.IsNotExist(err) {
		t.Fatal("incomplete evidence file was not removed")
	}

	boundedPath := filepath.Join(directory, "bounded")
	file, err := os.OpenFile(boundedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := &boundedOutputWriter{file: file, remaining: 3}
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("d")); err == nil || !writer.exceeded {
		t.Fatal("bounded writer accepted excess output")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReleasedScopeFixturesMatchLauncherContract(t *testing.T) {
	for _, engineID := range []string{"cloudquery", "steampipe", "prowler", "scoutsuite", "cloudsplaining"} {
		t.Run(engineID, func(t *testing.T) {
			document, err := loadScope(filepath.Join("testdata", "scope-"+engineID+".json"), engineID)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			if err := validateScopePermissions(document, engineID); err != nil {
				t.Fatalf("validate fixture permissions: %v", err)
			}
			if err := validateProviderForEngine(engineID, providerAWS, document); err != nil {
				t.Fatalf("validate fixture provider: %v", err)
			}
			if accountID, err := expectedAWSAccountID(document); err != nil || accountID != "000000000000" {
				t.Fatalf("validate fixture account binding: %q %v", accountID, err)
			}
		})
	}
}

func TestSteampipeQueryIsExactUpstreamIAMUserInventory(t *testing.T) {
	const expected = `select
  'aws_iam_user' as resource_type,
  account_id,
  arn,
  user_id,
  name
from aws_iam_user;
`
	if steampipeIAMUserInventoryQuery != expected {
		t.Fatalf("unexpected Steampipe inventory query:\n%s", steampipeIAMUserInventoryQuery)
	}

	normalized := strings.ToLower(steampipeIAMUserInventoryQuery)
	for _, forbidden := range []string{
		"mfa_enabled",
		"control_id",
		"status",
		"severity",
		"case when",
	} {
		if strings.Contains(normalized, forbidden) {
			t.Fatalf("Steampipe inventory query contains product-owned policy logic %q", forbidden)
		}
	}
}

func TestCloudQueryConfigurationIsExactLocalSourceClosure(t *testing.T) {
	config := string(cloudQueryConfiguration())
	tables := []string{
		"aws_iam_accounts",
		"aws_iam_credential_reports",
		"aws_iam_groups",
		"aws_iam_password_policies",
		"aws_iam_policies",
		"aws_iam_roles",
		"aws_iam_users",
	}
	for _, table := range tables {
		if strings.Count(config, "\n    - "+table+"\n") != 1 {
			t.Fatalf("fixed CloudQuery table %s is missing or duplicated", table)
		}
	}
	if strings.Count(config, "\n    - aws_") != len(tables) {
		t.Fatal("CloudQuery profile contains a table outside the exact allowlist")
	}
	for _, required := range []string{
		"path: /usr/local/libexec/cloudquery-source-aws",
		"path: /usr/local/libexec/cloudquery-destination-file",
		"registry: local",
		"regions: [us-east-1]",
		"directory: /output",
		"format: json",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("CloudQuery config lacks %q", required)
		}
	}
	for _, forbidden := range []string{
		"aws_iam_account_authorization_details",
		"cloudquery/aws",
		"cloudquery/file",
		"registry: grpc",
		"registry: github",
		"registry: cloudquery",
		"{{TABLE}}",
		"{{UUID}}",
	} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("CloudQuery config contains forbidden registry or schema value %q", forbidden)
		}
	}
}

// fakeGateway is a SOCKS5 server that records each CONNECT and, unless told to
// refuse, joins the tunnel to target whatever host the CONNECT named.
type fakeGateway struct {
	listener net.Listener
	target   string
	refuse   bool
	mutex    sync.Mutex
	requests []string
}

func startFakeGateway(t *testing.T, target string, refuse bool) *fakeGateway {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := &fakeGateway{listener: listener, target: target, refuse: refuse}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go gateway.serve(client)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return gateway
}

func (gateway *fakeGateway) serve(client net.Conn) {
	defer client.Close()
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(client, greeting); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(client, header); err != nil || header[3] != 3 {
		return
	}
	name := make([]byte, int(header[4])+2)
	if _, err := io.ReadFull(client, name); err != nil {
		return
	}
	port := int(name[header[4]])<<8 | int(name[header[4]+1])
	gateway.mutex.Lock()
	gateway.requests = append(gateway.requests, fmt.Sprintf("%s:%d", name[:header[4]], port))
	gateway.mutex.Unlock()
	if gateway.refuse {
		_, _ = client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	upstream, err := net.Dial("tcp4", gateway.target)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, client) }()
	_, _ = io.Copy(client, upstream)
}

func (gateway *fakeGateway) seen() []string {
	gateway.mutex.Lock()
	defer gateway.mutex.Unlock()
	return append([]string(nil), gateway.requests...)
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func openProviderTunnel(t *testing.T, bridge *providerBridge, target string) (net.Conn, string) {
	t.Helper()
	client, err := net.Dial("tcp4", bridge.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		return client, ""
	}
	_ = client.SetReadDeadline(time.Time{})
	return client, strings.TrimSpace(status)
}

func TestProviderBridgeCarriesAnHTTPSRequestThroughTheGateway(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "provider answer")
	}))
	defer server.Close()
	gateway := startFakeGateway(t, server.Listener.Addr().String(), false)
	bridge, err := startProviderBridge(gateway.listener.Addr().String(), 2, 100, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	trusted := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	trusted.ServerName = "example.com"
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: bridge.listener.Addr().String()}),
		TLSClientConfig: trusted,
	}}
	response, err := client.Get("https://iam.amazonaws.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "provider answer" {
		t.Fatalf("tunnel returned %q", body)
	}
	if seen := gateway.seen(); len(seen) != 1 || seen[0] != "iam.amazonaws.com:443" {
		t.Fatalf("gateway saw %v, want the provider host name and port", seen)
	}
}

func TestProviderBridgeRefusesWhatItCannotTunnel(t *testing.T) {
	gateway := startFakeGateway(t, startEchoServer(t), false)
	bridge, err := startProviderBridge(gateway.listener.Addr().String(), 2, 100, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	for _, target := range []string{"10.0.0.1:443", "[fd00::1]:443", "iam.amazonaws.com:80", "localhost:443", "iam..amazonaws.com:443"} {
		if _, status := openProviderTunnel(t, bridge, target); !strings.HasPrefix(status, "HTTP/1.1 403") {
			t.Fatalf("CONNECT %s answered %q, want 403", target, status)
		}
	}
	client, err := net.Dial("tcp4", bridge.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = io.WriteString(client, "GET http://iam.amazonaws.com/ HTTP/1.1\r\nHost: iam.amazonaws.com\r\n\r\n")
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if status, _ := bufio.NewReader(client).ReadString('\n'); !strings.HasPrefix(status, "HTTP/1.1 405") {
		t.Fatalf("plain proxy request answered %q, want 405", status)
	}
	if seen := gateway.seen(); len(seen) != 0 {
		t.Fatalf("refused requests reached the gateway: %v", seen)
	}

	refusing := startFakeGateway(t, startEchoServer(t), true)
	refused, err := startProviderBridge(refusing.listener.Addr().String(), 2, 100, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Close()
	if _, status := openProviderTunnel(t, refused, "billing.amazonaws.com:443"); !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("a destination the gateway refused answered %q, want 403", status)
	}
}

func TestProviderBridgeQueuesTunnelsBeyondItsLimit(t *testing.T) {
	gateway := startFakeGateway(t, startEchoServer(t), false)
	bridge, err := startProviderBridge(gateway.listener.Addr().String(), 1, 100, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	first, status := openProviderTunnel(t, bridge, "iam.amazonaws.com:443")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("first tunnel answered %q", status)
	}
	second, err := net.Dial("tcp4", bridge.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_, _ = io.WriteString(second, "CONNECT sts.us-east-1.amazonaws.com:443 HTTP/1.1\r\nHost: sts.us-east-1.amazonaws.com:443\r\n\r\n")
	reader := bufio.NewReader(second)
	_ = second.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if line, err := reader.ReadString('\n'); err == nil {
		t.Fatalf("second tunnel opened while the first held the only slot: %q", line)
	}
	_ = first.Close()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "HTTP/1.1 200 Connection established" {
		t.Fatalf("queued tunnel answered %q after the slot freed: %v", line, err)
	}
}

func TestProviderBridgeClosesIdleTunnelsAndFreesTheirSlot(t *testing.T) {
	gateway := startFakeGateway(t, startEchoServer(t), false)
	bridge, err := startProviderBridge(gateway.listener.Addr().String(), 1, 100, 200*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	tunnel, status := openProviderTunnel(t, bridge, "iam.amazonaws.com:443")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("tunnel answered %q", status)
	}
	_, _ = io.WriteString(tunnel, "ping")
	echo := make([]byte, 4)
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tunnel, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("tunnel did not carry traffic: %q %v", echo, err)
	}
	started := time.Now()
	if _, err := tunnel.Read(echo); err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("idle tunnel stayed open: %v after %s", err, time.Since(started))
	}
	if _, status := openProviderTunnel(t, bridge, "iam.amazonaws.com:443"); status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("slot was not freed by the idle close: %q", status)
	}
}

func TestProviderBridgeWaitsLongerForAnAnswerThanForTheNextRequest(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			return
		}
		time.Sleep(700 * time.Millisecond)
		_, _ = io.WriteString(connection, "pong")
		_, _ = io.Copy(io.Discard, connection)
	}()
	gateway := startFakeGateway(t, listener.Addr().String(), false)
	bridge, err := startProviderBridge(gateway.listener.Addr().String(), 1, 100, 200*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	tunnel, status := openProviderTunnel(t, bridge, "iam.amazonaws.com:443")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("tunnel answered %q", status)
	}
	_, _ = io.WriteString(tunnel, "ping")
	answer := make([]byte, 4)
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tunnel, answer); err != nil || string(answer) != "pong" {
		t.Fatalf("a slow answer was cut off: %q %v", answer, err)
	}
	started := time.Now()
	if _, err := tunnel.Read(answer); err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("tunnel stayed open after the answer: %v after %s", err, time.Since(started))
	}
}

func TestProviderBridgeCloseEndsOpenTunnels(t *testing.T) {
	gateway := startFakeGateway(t, startEchoServer(t), false)
	bridge, err := startProviderBridge(gateway.listener.Addr().String(), 2, 100, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, status := openProviderTunnel(t, bridge, "iam.amazonaws.com:443")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("tunnel answered %q", status)
	}
	closed := make(chan struct{})
	go func() {
		bridge.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not stop while a tunnel was open")
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel survived the bridge")
	}
}

func TestBridgeProviderTrafficPointsOnlyTheProxyVariablesAtTheBridge(t *testing.T) {
	gatewayURL := "socks5h://127.0.0.1:1080"
	environment := []string{"AI_SECURITY_SCANNER_PROXY=" + gatewayURL, "AWS_REGION=us-east-1", "NO_PROXY=", "no_proxy="}
	for _, key := range bridgedProxyKeys {
		environment = append(environment, key+"="+gatewayURL)
	}
	sort.Strings(environment)
	bridged, bridge, err := bridgeProviderTraffic(environment)
	if err != nil || bridge == nil {
		t.Fatalf("managed gateway was not bridged: %v", err)
	}
	defer bridge.Close()
	values := map[string]string{}
	for _, entry := range bridged {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	proxy := "http://" + bridge.listener.Addr().String()
	for _, key := range bridgedProxyKeys {
		if values[key] != proxy {
			t.Fatalf("%s=%q, want the loopback bridge %q", key, values[key], proxy)
		}
	}
	if values["AI_SECURITY_SCANNER_PROXY"] != gatewayURL || values["AWS_REGION"] != "us-east-1" ||
		values["NO_PROXY"] != "" || len(bridged) != len(environment) {
		t.Fatalf("bridging changed more than the proxy variables: %v", bridged)
	}

	unmanaged := []string{"AWS_REGION=us-east-1"}
	if same, none, err := bridgeProviderTraffic(unmanaged); err != nil || none != nil || len(same) != 1 {
		t.Fatalf("an engine run without a managed gateway changed: %v %v %v", same, none, err)
	}
	for _, malformed := range []string{
		"", "socks5h://gateway:1080", "socks5://127.0.0.1:1080", "socks5h://127.0.0.1:1081",
		"socks5h://user@127.0.0.1:1080", "http://127.0.0.1:1080", "socks5h://127.0.0.1:1080/path",
	} {
		if _, rejected, err := bridgeProviderTraffic([]string{"AI_SECURITY_SCANNER_PROXY=" + malformed}); err == nil || rejected != nil {
			t.Fatalf("malformed gateway %q was bridged", malformed)
		}
	}
}

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureDocument(engineID string, now time.Time) *scopeDocument {
	permission := "low_impact_external_connection"
	activity := "low_impact_external"
	template := templatePolicy{Revision: "not_applicable"}
	kind := "web_service"
	if engineID == "naabu" {
		kind = "host"
	}
	if engineID == "nuclei" {
		permission = "active_external_testing"
		activity = "active_external"
		template = templatePolicy{
			Revision:           "nuclei-templates@" + templateRevision,
			AllowedTemplateIDs: []string{"safe-template"},
		}
	}
	makeAsset := func(assetID, grantID, target string, ports []uint16) scopeAsset {
		approved := now.Add(-time.Minute)
		expires := now.Add(time.Hour)
		return scopeAsset{
			ID: assetID, Name: target, Kind: kind,
			Identifiers: []identifier{{Namespace: "dns:name", Value: target}},
			Grants: []scopeGrant{{
				ID: grantID, Permission: permission, ConfirmedBy: "owner@example.test",
				ConfirmedAt: approved, ExpiresAt: &expires,
				AuthorizationReference: stringPointer("ticket SEC-1042"),
				ExternalScope: &externalScope{
					ID: grantID, CaseID: "case-1", AssetID: assetID,
					Target: canonicalTarget{Kind: "hostname", Value: target}, Ports: ports,
					Protocol: "https", Activity: activity,
					RatePolicy:     ratePolicy{RequestsPerSecond: 2, Concurrency: 2, TimeoutSeconds: 30},
					TemplatePolicy: template, AssertedAuthority: "ticket SEC-1042",
					ApprovedBy: "owner@example.test", ApprovedAt: approved, ExpiresAt: expires,
				},
			}},
		}
	}
	return &scopeDocument{
		SchemaVersion: "1", EngineID: engineID, GeneratedAt: now,
		Assets: []scopeAsset{
			makeAsset("asset-a", "grant-a", "a.example.test", []uint16{443, 8443}),
			makeAsset("asset-b", "grant-b", "b.example.test", []uint16{9443}),
		},
	}
}

func stringPointer(value string) *string { return &value }

func TestPlansEachGrantWithoutTargetPortCrossProduct(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	httpUnits, err := validateAndPlan(fixtureDocument("httpx", now), "httpx", now)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(httpUnits))
	for _, unit := range httpUnits {
		got = append(got, unit.Grant.Target.Value+":"+portText(unit.Port))
	}
	want := []string{"a.example.test:443", "a.example.test:8443", "b.example.test:9443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grant-local plans differ: got %v want %v", got, want)
	}

	naabuUnits, err := validateAndPlan(fixtureDocument("naabu", now), "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(naabuUnits) != 2 || !reflect.DeepEqual(naabuUnits[0].Grant.Ports, []uint16{443, 8443}) || !reflect.DeepEqual(naabuUnits[1].Grant.Ports, []uint16{9443}) {
		t.Fatalf("Naabu grants were combined: %#v", naabuUnits)
	}
}

func TestStaticInvocationsCarryEveryFrozenLimit(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("httpx", now)
	units, err := validateAndPlan(document, "httpx", now)
	if err != nil {
		t.Fatal(err)
	}
	environment := childEnvironment("socks5h://172.30.0.1:1080", "/tmp/private")
	httpx, err := httpxInvocation(units[0], "socks5h://172.30.0.1:1080", "/tmp/out", environment)
	if err != nil {
		t.Fatal(err)
	}
	joined := " " + strings.Join(httpx.Args, " ") + " "
	for _, exact := range []string{
		" -target https://a.example.test:443 ", " -proxy socks5h://172.30.0.1:1080 ",
		" -rate-limit 2 ", " -threads 2 ", " -timeout 30 ", " -retries 0 ",
		" -no-fallback-scheme ", " -no-stdin ", " -disable-update-check ",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("httpx invocation lacks %q: %s", exact, joined)
		}
	}

	nucleiProxy := nucleiCompatibleProxy("socks5h://172.30.0.1:1080")
	if nucleiProxy != "socks5://172.30.0.1:1080" {
		t.Fatalf("Nuclei proxy compatibility spelling changed: %s", nucleiProxy)
	}
	nucleiDocument := fixtureDocument("nuclei", now)
	nucleiUnits, err := validateAndPlan(nucleiDocument, "nuclei", now)
	if err != nil {
		t.Fatal(err)
	}
	nucleiEnvironment := childEnvironment(nucleiProxy, "/tmp/private")
	nuclei, err := nucleiInvocation(
		nucleiUnits[0], nucleiProxy, "/tmp/out", nucleiEnvironment, t.TempDir(), 0,
		[]string{"/opt/nuclei-templates/http/safe-template.yaml"},
	)
	if err != nil {
		t.Fatal(err)
	}
	joined = " " + strings.Join(nuclei.Args, " ") + " "
	for _, exact := range []string{
		" -target https://a.example.test:443 ", " -proxy socks5://172.30.0.1:1080 ",
		" -rate-limit 2 ", " -bulk-size 2 ", " -concurrency 2 ", " -timeout 30 ",
		" -no-httpx ", " -no-interactsh ", " -disable-redirects ", " -no-stdin ",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("Nuclei invocation lacks %q: %s", exact, joined)
		}
	}
	if strings.Contains(strings.Join(nuclei.Env, "\n"), "socks5h://") {
		t.Fatal("Nuclei child environment retained a proxy spelling its parser rejects")
	}

	naabuDocument := fixtureDocument("naabu", now)
	naabuUnits, err := validateAndPlan(naabuDocument, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	naabu := naabuInvocation(naabuUnits[0], "172.30.0.1:1080", "/tmp/out", environment)
	joined = " " + strings.Join(naabu.Args, " ") + " "
	for _, exact := range []string{
		" -host a.example.test ", " -port 443,8443 ", " -scan-type c ", " -dns-order p ",
		" -proxy 172.30.0.1:1080 ", " -rate 2 ", " -c 2 ", " -timeout 30s ",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("Naabu invocation lacks %q: %s", exact, joined)
		}
	}
}

func TestManagedProxyRequiresExactBridgeSocksEndpoint(t *testing.T) {
	canonical, naabu, err := managedProxy("socks5h://172.31.0.1:1080")
	if err != nil || canonical != "socks5h://172.31.0.1:1080" || naabu != "172.31.0.1:1080" {
		t.Fatalf("managed proxy rejected: %q %q %v", canonical, naabu, err)
	}
	for _, value := range []string{
		"", "http://172.31.0.1:1080", "socks5://172.31.0.1:1080",
		"socks5h://user:pass@172.31.0.1:1080", "socks5h://gateway:1080",
		"socks5h://172.31.0.1:1081", "socks5h://172.31.0.1:1080/path",
	} {
		if _, _, err := managedProxy(value); err == nil {
			t.Fatalf("unsafe proxy endpoint accepted: %s", value)
		}
	}
}

func TestNucleiTemplateIndexAllowsOnlyBoundedReadOnlyHTTP(t *testing.T) {
	root := t.TempDir()
	safe := `id: safe-template
info:
  name: Safe fixture
  severity: info
  metadata:
    max-request: 1
  tags: misconfig
http:
  - method: GET
    path:
      - "{{BaseURL}}/security.txt"
`
	unsafe := strings.Replace(safe, "method: GET", "method: POST\n    body: data", 1)
	if err := os.WriteFile(filepath.Join(root, "safe.yaml"), []byte(safe), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unsafe.yaml"), []byte(strings.Replace(unsafe, "safe-template", "unsafe-template", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := loadTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"safe-template"}}, index)
	if err != nil || len(paths) != 1 {
		t.Fatalf("safe template rejected: %v", err)
	}
	if _, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"unsafe-template"}}, index); err == nil {
		t.Fatal("POST/body template was accepted")
	}
	if _, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"missing"}}, index); err == nil {
		t.Fatal("template outside exact embedded revision was accepted")
	}
}

func TestPinnedNucleiTemplateTreeWhenProvided(t *testing.T) {
	root := os.Getenv("NUCLEI_TEMPLATE_ROOT")
	if root == "" {
		t.Skip("exact template tree is supplied by the image smoke")
	}
	index, err := loadTemplateIndex(filepath.Join(root, "http"))
	if err != nil {
		t.Fatalf("index exact template tree: %v", err)
	}
	if len(index) < 1000 {
		t.Fatalf("exact template tree unexpectedly small: %d", len(index))
	}
	paths, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"CVE-2018-16671"}}, index)
	if err != nil || len(paths) != 1 {
		t.Fatalf("known bounded GET template failed conservative policy: %v", err)
	}
}

func TestEvidenceIsReattributedAndOutOfScopeRecordsFail(t *testing.T) {
	unit := scanUnit{
		AssetID: "asset-a",
		Grant: externalScope{
			ID: "grant-a", Target: canonicalTarget{Kind: "hostname", Value: "a.example.test"},
			Ports: []uint16{443}, Protocol: "https",
			TemplatePolicy: templatePolicy{AllowedTemplateIDs: []string{"safe-template"}},
		},
		Port: 443,
	}
	path := filepath.Join(t.TempDir(), "httpx.jsonl")
	if err := os.WriteFile(path, []byte(`{"url":"https://a.example.test:443/","status_code":200,"body":"discard me"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	written := int64(0)
	if err := normalizeEvidence(path, writer, &written, "httpx", unit); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record["asset_id"] != "asset-a" || record["scope_grant_id"] != "grant-a" || record["body"] != nil {
		t.Fatalf("unexpected normalized evidence: %#v", record)
	}

	if err := os.WriteFile(path, []byte(`{"url":"https://b.example.test:443/","status_code":200}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer = bufio.NewWriter(&bytes.Buffer{})
	written = 0
	if err := normalizeEvidence(path, writer, &written, "httpx", unit); err == nil {
		t.Fatal("out-of-scope evidence was accepted")
	}
}

func TestScopeDecoderRejectsUnknownFields(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("httpx", now)
	value, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	value = bytes.Replace(value, []byte(`"engine_id":"httpx"`), []byte(`"engine_id":"httpx","unexpected":true`), 1)
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path, "httpx"); err == nil {
		t.Fatal("unknown scope field was accepted")
	}
}

func portText(port uint16) string { return strconv.Itoa(int(port)) }

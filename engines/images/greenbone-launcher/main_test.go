package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	selectedOID = "1.3.6.1.4.1.25623.1.0.10107"
	settingOID  = "1.3.6.1.4.1.25623.1.0.103978"
	implicitOID = "1.3.6.1.4.1.25623.1.0.900239"
	unsafeOID   = "1.3.6.1.4.1.25623.1.0.999999"
)

func validScope(now time.Time) *scopeDocument {
	target := "198.51.100.7"
	confirmedBy := "security-owner@example.test"
	authorization := "change-record-123"
	expires := now.Add(2 * time.Hour)
	external := externalScope{
		ID:                     "grant-1",
		CaseID:                 "case-1",
		AssetID:                "asset-1",
		Target:                 canonicalTarget{Kind: "address", Value: target},
		Ports:                  []uint16{80, 443},
		Protocol:               "https",
		Activity:               "active_external",
		RatePolicy:             ratePolicy{RequestsPerSecond: 2, Concurrency: 1, TimeoutSeconds: 30},
		TemplatePolicy:         templatePolicy{Revision: templateRevision, AllowedTemplateIDs: []string{selectedOID}},
		AssertedAuthority:      "I own and authorize testing of this exact target.",
		ApprovedBy:             confirmedBy,
		ApprovedAt:             now.Add(-time.Minute),
		ExpiresAt:              expires,
		AllowSensitiveNetworks: false,
	}
	return &scopeDocument{
		SchemaVersion: "1",
		EngineID:      engineID,
		GeneratedAt:   now,
		Assets: []scopeAsset{{
			ID:          "asset-1",
			Name:        "Authorized service",
			Kind:        "ip_address",
			Identifiers: []identifier{{Namespace: "ip", Value: target}},
			Grants: []scopeGrant{{
				ID:                     "grant-1",
				Permission:             "active_external_testing",
				ConfirmedBy:            confirmedBy,
				ConfirmedAt:            external.ApprovedAt,
				ExpiresAt:              &expires,
				AuthorizationReference: &authorization,
				ExternalScope:          &external,
			}},
		}},
	}
}

func testFeed() *feedIndex {
	selected := vtMetadata{
		OID:          selectedOID,
		Name:         "HTTP banner <detector>",
		Filename:     "http_version.nasl",
		Category:     "gather_info",
		Family:       "Service detection",
		Dependencies: []string{"global_settings.nasl"},
		References:   []metadataReference{{Class: "cve", ID: "cve-2024-12345"}},
		Tag: metadataTag{
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			QODType:        "remote_banner",
			Solution:       "Upgrade & verify.",
		},
	}
	setting := vtMetadata{OID: settingOID, Name: "Settings", Filename: "global_settings.nasl", Category: "settings", Family: "Settings"}
	implicit := vtMetadata{OID: implicitOID, Name: "Open ports", Filename: "open_ports.nasl", Category: "gather_info", Family: "General"}
	tcpScanner := vtMetadata{OID: tcpScannerOID, Name: "OpenVAS TCP scanner", Filename: tcpScannerFilename, Category: "scanner", Family: "Port scanners"}
	unsafe := vtMetadata{OID: unsafeOID, Name: "Unsafe", Filename: "unsafe.nasl", Category: "attack", Family: "Attack"}
	return &feedIndex{
		ByOID: map[string]vtMetadata{
			selectedOID:   selected,
			settingOID:    setting,
			implicitOID:   implicit,
			tcpScannerOID: tcpScanner,
			unsafeOID:     unsafe,
		},
		ByFilename: map[string]string{
			selected.Filename:   selectedOID,
			setting.Filename:    settingOID,
			implicit.Filename:   implicitOID,
			tcpScanner.Filename: tcpScannerOID,
			unsafe.Filename:     unsafeOID,
		},
	}
}

func testRelays() *unitRelays {
	return &unitRelays{
		target:         "127.0.0.1",
		byRelayPort:    map[uint16]uint16{40080: 80, 40443: 443},
		byOriginalPort: map[uint16]uint16{80: 40080, 443: 40443},
	}
}

func TestValidateAndPlanAcceptsExactActiveExternalGrant(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	units, err := validateAndPlan(validScope(now), now)
	if err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
	if len(units) != 1 || units[0].AssetID != "asset-1" || units[0].Grant.Target.Value != "198.51.100.7" {
		t.Fatalf("unexpected plan: %#v", units)
	}
}

func TestValidateAndPlanRejectsExpandedAuthority(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*scopeDocument)
	}{
		{"denial of service", func(document *scopeDocument) {
			document.Assets[0].Grants[0].ExternalScope.TemplatePolicy.AllowDenialOfService = true
		}},
		{"network expansion", func(document *scopeDocument) { document.Assets[0].Grants[0].ExternalScope.Target.Kind = "network" }},
		{"unsorted ports", func(document *scopeDocument) { document.Assets[0].Grants[0].ExternalScope.Ports = []uint16{443, 80} }},
		{"wrong revision", func(document *scopeDocument) {
			document.Assets[0].Grants[0].ExternalScope.TemplatePolicy.Revision = "latest"
		}},
		{"expired", func(document *scopeDocument) {
			expires := now.Add(-time.Second)
			document.Assets[0].Grants[0].ExpiresAt = &expires
			document.Assets[0].Grants[0].ExternalScope.ExpiresAt = expires
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validScope(now)
			test.mutate(document)
			if _, err := validateAndPlan(document, now); err == nil {
				t.Fatal("expanded or invalid grant was accepted")
			}
		})
	}
}

func TestManagedProxyRequiresFrozenIPv4BridgeEndpoint(t *testing.T) {
	proxy, err := managedProxy("socks5h://172.29.0.2:1080")
	if err != nil || proxy.String() != "socks5h://172.29.0.2:1080" {
		t.Fatalf("valid managed endpoint rejected: %v, %v", proxy, err)
	}
	for _, value := range []string{
		"socks5://172.29.0.2:1080",
		"socks5h://gateway:1080",
		"socks5h://172.29.0.2:1081",
		"socks5h://user@172.29.0.2:1080",
		"socks5h://[fd00::2]:1080",
	} {
		if _, err := managedProxy(value); err == nil {
			t.Fatalf("invalid endpoint accepted: %s", value)
		}
	}
}

func TestUnitRelayUsesExactSOCKSConnect(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	targetPort := uint16(targetListener.Addr().(*net.TCPAddr).Port)
	targetDone := make(chan error, 1)
	go func() {
		connection, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		defer connection.Close()
		value := make([]byte, 4)
		if _, acceptErr = io.ReadFull(connection, value); acceptErr == nil {
			_, acceptErr = connection.Write(value)
		}
		targetDone <- acceptErr
	}()

	gatewayListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayListener.Close()
	gatewayDone := make(chan error, 1)
	go func() {
		client, acceptErr := gatewayListener.Accept()
		if acceptErr != nil {
			gatewayDone <- acceptErr
			return
		}
		defer client.Close()
		greeting := make([]byte, 3)
		if _, acceptErr = io.ReadFull(client, greeting); acceptErr != nil || !bytes.Equal(greeting, []byte{5, 1, 0}) {
			gatewayDone <- acceptErr
			return
		}
		if _, acceptErr = client.Write([]byte{5, 0}); acceptErr != nil {
			gatewayDone <- acceptErr
			return
		}
		request := make([]byte, 10)
		if _, acceptErr = io.ReadFull(client, request); acceptErr != nil {
			gatewayDone <- acceptErr
			return
		}
		expected := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort)}
		if !bytes.Equal(request, expected) {
			gatewayDone <- &net.AddrError{Err: "unexpected SOCKS request", Addr: string(request)}
			return
		}
		upstream, acceptErr := net.Dial("tcp4", targetListener.Addr().String())
		if acceptErr != nil {
			gatewayDone <- acceptErr
			return
		}
		defer upstream.Close()
		if _, acceptErr = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); acceptErr != nil {
			gatewayDone <- acceptErr
			return
		}
		copied := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, client); copied <- struct{}{} }()
		go func() { _, _ = io.Copy(client, upstream); copied <- struct{}{} }()
		<-copied
		gatewayDone <- nil
	}()

	document := validScope(time.Now().UTC())
	unit := scanUnit{AssetID: document.Assets[0].ID, Grant: *document.Assets[0].Grants[0].ExternalScope}
	unit.Grant.Target = canonicalTarget{Kind: "address", Value: "127.0.0.1"}
	unit.Grant.Ports = []uint16{targetPort}
	gateway, err := url.Parse("socks5h://" + gatewayListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	relays, err := startUnitRelays(context.Background(), unit, gateway)
	if err != nil {
		t.Fatal(err)
	}
	defer relays.Close()
	relayPort := relays.byOriginalPort[targetPort]
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort(relays.target, strconv.Itoa(int(relayPort))), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err = io.ReadFull(connection, response); err != nil || string(response) != "ping" {
		t.Fatalf("relay response %q: %v", response, err)
	}
	_ = connection.Close()
	select {
	case err = <-targetDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive relayed traffic")
	}
}

func TestFeedSelectionClosesOnlySafeDependencies(t *testing.T) {
	feed := testFeed()
	closure, err := feed.validateSafeSelection([]string{selectedOID})
	if err != nil {
		t.Fatalf("safe closure rejected: %v", err)
	}
	if _, ok := closure[selectedOID]; !ok {
		t.Fatal("selected OID absent from closure")
	}
	if _, ok := closure[settingOID]; !ok {
		t.Fatal("safe dependency absent from closure")
	}
	if _, ok := closure[tcpScannerOID]; !ok {
		t.Fatal("fixed unprivileged TCP scanner absent from closure")
	}
	if _, err := feed.validateSafeSelection([]string{unsafeOID}); err == nil {
		t.Fatal("direct unsafe OID was accepted")
	}
	selected := feed.ByOID[selectedOID]
	selected.Dependencies = []string{"unsafe.nasl"}
	feed.ByOID[selectedOID] = selected
	if _, err := feed.validateSafeSelection([]string{selectedOID}); err == nil {
		t.Fatal("unsafe transitive dependency was accepted")
	}
}

func TestBuildScanRequestPreservesExactTargetPortsAndRate(t *testing.T) {
	document := validScope(time.Now().UTC())
	unit := scanUnit{AssetID: document.Assets[0].ID, Grant: *document.Assets[0].Grants[0].ExternalScope}
	unit.Grant.TemplatePolicy.AllowedTemplateIDs = []string{settingOID, selectedOID}
	request := buildScanRequest(unit, testRelays())
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	for _, expected := range []string{
		`"hosts":["127.0.0.1"]`,
		`"protocol":"tcp"`,
		`"start":40080,"end":40080`,
		`"start":40443,"end":40443`,
		`"alive_test_methods":["consider_alive"]`,
		`"id":"safe_checks","value":"yes"`,
		`"id":"time_between_request","value":"500"`,
		`"credentials":[]`,
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("request missing %s: %s", expected, value)
		}
	}
	if len(request.VTs) != 3 || request.VTs[0].OID != selectedOID || request.VTs[1].OID != tcpScannerOID || request.VTs[2].OID != settingOID {
		t.Fatalf("VT selection is not deterministic: %#v", request.VTs)
	}
}

func TestRunUnitCancellationStopsAndDeletesExactScan(t *testing.T) {
	const scanID = "123e4567-e89b-12d3-a456-426614174000"
	type observedRequest struct {
		method string
		path   string
		action string
	}
	requests := make([]observedRequest, 0, 5)
	statusRequested := make(chan struct{})
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		observed := observedRequest{method: request.Method, path: request.URL.Path}
		if request.Body != nil && request.URL.Path == "/scans/"+scanID {
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				return nil, err
			}
			observed.action = body["action"]
		}
		requests = append(requests, observed)
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/scans":
			return testHTTPResponse(http.StatusCreated, `"`+scanID+`"`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/scans/"+scanID && observed.action == "start":
			return testHTTPResponse(http.StatusNoContent, ""), nil
		case request.Method == http.MethodGet && request.URL.Path == "/scans/"+scanID+"/status":
			close(statusRequested)
			<-request.Context().Done()
			return nil, request.Context().Err()
		case request.Method == http.MethodPost && request.URL.Path == "/scans/"+scanID && observed.action == "stop":
			return testHTTPResponse(http.StatusNoContent, ""), nil
		case request.Method == http.MethodDelete && request.URL.Path == "/scans/"+scanID:
			return testHTTPResponse(http.StatusNoContent, ""), nil
		default:
			return testHTTPResponse(http.StatusNotFound, ""), nil
		}
	})
	api := &openvasdClient{client: &http.Client{Transport: transport}, key: "test-key"}
	document := validScope(time.Now().UTC())
	unit := scanUnit{AssetID: document.Assets[0].ID, Grant: *document.Assets[0].Grants[0].ExternalScope}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := api.runUnit(ctx, unit, testRelays())
		result <- err
	}()
	select {
	case <-statusRequested:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not reach status polling")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled scan returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled scan did not return after cleanup")
	}
	expected := []observedRequest{
		{method: http.MethodPost, path: "/scans"},
		{method: http.MethodPost, path: "/scans/" + scanID, action: "start"},
		{method: http.MethodGet, path: "/scans/" + scanID + "/status"},
		{method: http.MethodPost, path: "/scans/" + scanID, action: "stop"},
		{method: http.MethodDelete, path: "/scans/" + scanID},
	}
	if len(requests) != len(expected) {
		t.Fatalf("cleanup request count = %d, want %d: %#v", len(requests), len(expected), requests)
	}
	for index := range expected {
		if requests[index] != expected[index] {
			t.Fatalf("request %d = %#v, want %#v", index, requests[index], expected[index])
		}
	}
}

func TestStopProcessGroupUsesNegativePIDAndEscalates(t *testing.T) {
	command := &exec.Cmd{Process: &os.Process{Pid: 4321}}
	t.Run("graceful", func(t *testing.T) {
		exited := make(chan error, 1)
		var signals []syscall.Signal
		stopProcessGroup(command, exited, time.Second, func(pid int, signal syscall.Signal) error {
			if pid != -command.Process.Pid {
				t.Fatalf("signal target = %d, want process group %d", pid, -command.Process.Pid)
			}
			signals = append(signals, signal)
			exited <- nil
			return nil
		})
		if len(signals) != 1 || signals[0] != syscall.SIGTERM {
			t.Fatalf("graceful signals = %v, want [SIGTERM]", signals)
		}
	})
	t.Run("forced", func(t *testing.T) {
		exited := make(chan error, 1)
		var signals []syscall.Signal
		stopProcessGroup(command, exited, time.Millisecond, func(pid int, signal syscall.Signal) error {
			if pid != -command.Process.Pid {
				t.Fatalf("signal target = %d, want process group %d", pid, -command.Process.Pid)
			}
			signals = append(signals, signal)
			if signal == syscall.SIGKILL {
				exited <- nil
			}
			return nil
		})
		if len(signals) != 2 || signals[0] != syscall.SIGTERM || signals[1] != syscall.SIGKILL {
			t.Fatalf("forced signals = %v, want [SIGTERM SIGKILL]", signals)
		}
	})
}

func TestValidateResultSeparatesAlarmClosureFromSafeSystemLogs(t *testing.T) {
	feed := testFeed()
	document := validScope(time.Now().UTC())
	unit := scanUnit{AssetID: document.Assets[0].ID, Grant: *document.Assets[0].Grants[0].ExternalScope}
	relays := testRelays()
	closure := map[string]struct{}{selectedOID: {}, settingOID: {}}
	validAlarm := scanResult{ID: 1, Type: "alarm", IPAddress: "127.0.0.1", OID: selectedOID, Port: 40080, Protocol: "tcp", Message: "detected"}
	if err := validateResult(validAlarm, unit, relays, closure, feed); err != nil {
		t.Fatalf("valid alarm rejected: %v", err)
	}
	if err := validateResult(scanResult{ID: 2, Type: "log", IPAddress: "127.0.0.1", OID: implicitOID, Protocol: "udp"}, unit, relays, map[string]struct{}{}, feed); err != nil {
		t.Fatalf("safe implicit log rejected: %v", err)
	}
	for name, result := range map[string]scanResult{
		"alarm outside closure": {ID: 3, Type: "alarm", IPAddress: "127.0.0.1", OID: implicitOID, Port: 40080, Protocol: "tcp"},
		"alarm outside ports":   {ID: 4, Type: "alarm", OID: selectedOID, Port: 22, Protocol: "tcp"},
		"unsafe log":            {ID: 5, Type: "log", OID: unsafeOID},
		"missing oid":           {ID: 6, Type: "host_start"},
		"non-loopback result":   {ID: 7, Type: "log", IPAddress: "198.51.100.7", OID: implicitOID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateResult(result, unit, relays, closure, feed); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
}

func TestWriteXMLResultProducesEscapedAdapterEvidence(t *testing.T) {
	feed := testFeed()
	document := validScope(time.Now().UTC())
	unit := scanUnit{AssetID: document.Assets[0].ID, Grant: *document.Assets[0].Grants[0].ExternalScope}
	result := scanResult{ID: 9, Type: "alarm", IPAddress: "127.0.0.1", OID: selectedOID, Port: 40443, Protocol: "tcp", Message: "found <risk> & evidence"}
	var output bytes.Buffer
	if err := writeXMLResult(&output, 0, result, unit, testRelays(), feed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "&lt;risk&gt; &amp; evidence") || !strings.Contains(output.String(), `type="cve" id="CVE-2024-12345"`) {
		t.Fatalf("XML did not preserve escaped evidence and normalized CVE: %s", output.String())
	}
	if !strings.Contains(output.String(), "<port>443/tcp</port>") || !strings.Contains(output.String(), "<raw_port>40443/tcp</raw_port>") {
		t.Fatalf("XML lost the authorized projection or raw relay provenance: %s", output.String())
	}
	var decoded any
	if err := xml.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("generated result is not XML: %v", err)
	}
}

func TestCVSSScores(t *testing.T) {
	for vector, expected := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
	} {
		if actual := cvssBaseScore(vector); math.Abs(actual-expected) > 0.001 {
			t.Errorf("%s = %.1f, want %.1f", vector, actual, expected)
		}
	}
	if score := cvss2BaseScore("AV:N/AC:L/Au:N/C:P/I:N/A:N"); math.Abs(score-5.0) > 0.001 {
		t.Errorf("CVSS v2 score = %.1f, want 5.0", score)
	}
	if cvssBaseScore("AV:N/AC:L") != 0 || cvss2BaseScore("not-a-vector") != 0 {
		t.Fatal("malformed vector produced a non-zero score")
	}
}

func TestLoadScopeRejectsUnknownAndTrailingFields(t *testing.T) {
	now := time.Now().UTC()
	directory := t.TempDir()
	path := filepath.Join(directory, "scope.json")
	valid, err := json.Marshal(validScope(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path); err != nil {
		t.Fatalf("valid scope failed to load: %v", err)
	}
	invalid := append([]byte(nil), valid[:len(valid)-1]...)
	invalid = append(invalid, []byte(`,"unexpected":true}`)...)
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path); err == nil {
		t.Fatal("unknown scope field was accepted")
	}
	if err := os.WriteFile(path, append(valid, []byte(` {}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path); err == nil {
		t.Fatal("trailing scope object was accepted")
	}
}

func TestBoundedWriterFailsClosed(t *testing.T) {
	var output bytes.Buffer
	writer := &boundedWriter{writer: &output, limit: 4}
	if _, err := writer.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("5")); err == nil {
		t.Fatal("writer exceeded evidence bound")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func testHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

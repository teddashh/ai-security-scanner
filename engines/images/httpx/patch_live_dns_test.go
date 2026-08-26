package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPinnedSourceTransformsToTheReviewedHashWhenProvided(t *testing.T) {
	path := os.Getenv("HTTPX_PINNED_RUNNER")
	if path == "" {
		t.Skip("pinned upstream runner source is supplied by the source-patch test")
	}
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	patched, err := patchPinnedSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(patched); got != expectedPatchedSHA {
		t.Fatalf("patched source digest differs: got %s want %s", got, expectedPatchedSHA)
	}
}

func TestReviewedReplacementRemovesOnlyPostRequestLiveDNS(t *testing.T) {
	source := []byte("prefix\n" + liveDNSBlock + "suffix\n")
	patched, err := replaceReviewedBlock(source)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(patched, []byte("getDNSData(hp, onlyHost)")) {
		t.Fatal("post-request live DNS call survived the reviewed patch")
	}
	if !bytes.Contains(patched, []byte(frozenDNSBlock)) || !bytes.HasPrefix(patched, []byte("prefix\n")) || !bytes.HasSuffix(patched, []byte("suffix\n")) {
		t.Fatal("reviewed patch changed bytes outside the exact live-DNS block")
	}
	if !strings.Contains(string(patched), "HTTP Host value and TLS SNI") {
		t.Fatal("patched source does not preserve the hostname request contract")
	}
}

func TestReviewedReplacementRejectsAbsentDuplicateAndAlreadyPatchedBlocks(t *testing.T) {
	for name, source := range map[string][]byte{
		"absent":          []byte("no reviewed block"),
		"duplicate":       []byte(liveDNSBlock + liveDNSBlock),
		"already_patched": []byte(liveDNSBlock + frozenDNSBlock),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := replaceReviewedBlock(source); err == nil {
				t.Fatal("unsafe source shape was accepted")
			}
		})
	}
}

func TestPatchCLIIsBoundToThePinnedContainerPath(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"--source", "runner/runner.go"},
		{"--source", expectedSourcePath, "extra"},
		{"--other", expectedSourcePath},
	} {
		if err := run(arguments); err == nil {
			t.Fatalf("unsafe patch arguments were accepted: %#v", arguments)
		}
	}
}

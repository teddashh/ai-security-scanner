"""Capability boundary tests; native detector behavior is exercised separately."""
import copy
import datetime
import importlib.util
import io
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher, runner = load("main"), load("runner")
NOW = datetime.datetime(2026, 10, 4, tzinfo=datetime.timezone.utc)


def scope():
    return {"schema_version": "1", "engine_id": "garak", "generated_at": NOW.isoformat(), "assets": [{
        "id": "fixture-model", "kind": "ai_model_endpoint", "identifiers": [
            {"namespace": "ai-security-scanner:model-endpoint", "value": "https://model.example.test/v1/chat/completions"},
            {"namespace": "ai-security-scanner:model-id", "value": "fixture/model"}],
        "grants": [{"permission": "active_external_testing", "authorization_reference": "fixture-owner",
                    "confirmed_by": "fixture owner", "confirmed_at": NOW.isoformat(), "expires_at": None,
                    "external_scope": {"asset_id": "fixture-model", "target": {"kind": "hostname", "value": "model.example.test"},
                                       "ports": [443], "protocol": "https", "activity": "active_external",
                                       "rate_policy": {"requests_per_second": 1, "concurrency": 1, "timeout_seconds": 20},
                                       "approved_at": NOW.isoformat(), "expires_at": (NOW + datetime.timedelta(minutes=30)).isoformat(),
                                       "approved_by": "fixture owner", "asserted_authority": "owned fixture",
                                       "template_policy": {"revision": launcher.SOURCE_REVISION, "profile_id": "garak_https_v1",
                                                           "allowed_template_ids": [],
                                                           **{f: False for f in ("allow_headless", "allow_out_of_band", "allow_fuzzing",
                                                                               "allow_file_upload", "allow_denial_of_service", "allow_credential_attacks")}}}}]}]}


class ScopeTests(unittest.TestCase):
    def test_exact_https_model_profile_and_expiry(self):
        self.assertEqual(launcher.validate_scope(scope(), NOW), ("https://model.example.test/v1/chat/completions", "fixture/model", 600))
        for change in (lambda s: s["assets"].append(copy.deepcopy(s["assets"][0])),
                       lambda s: s["assets"][0]["grants"].append(copy.deepcopy(s["assets"][0]["grants"][0])),
                       lambda s: s["assets"][0]["identifiers"].append(copy.deepcopy(s["assets"][0]["identifiers"][0])),
                       lambda s: s["assets"][0].update(kind="web_service")):
            value = scope()
            change(value)
            with self.assertRaises(launcher.Rejected):
                launcher.validate_scope(value, NOW)
        for field, value in (("ports", [443, 8443]), ("activity", "low_impact_external"),
                             ("protocol", "http"), ("expires_at", NOW.isoformat()),
                             ("target", {"kind": "hostname", "value": "other.example.test"})):
            changed = scope()
            changed["assets"][0]["grants"][0]["external_scope"][field] = value
            with self.assertRaises(launcher.Rejected):
                launcher.validate_scope(changed, NOW)
        changed = scope()
        changed["assets"][0]["grants"][0]["external_scope"]["template_policy"]["allow_headless"] = True
        with self.assertRaises(launcher.Rejected):
            launcher.validate_scope(changed, NOW)

    def test_endpoint_cannot_widen_or_smuggle_credentials(self):
        for endpoint in ("http://model.example.test/v1/chat/completions", "https://key@model.example.test/v1/chat/completions",
                         "https://model.example.test/", "https://model.example.test/a/../b", "https://model.example.test/a%2fb",
                         "https://model.example.test/a?key=secret", "https://model.example.test/a#other", "https://model.example.test/a\n"):
            with self.assertRaises(launcher.Rejected, msg=endpoint):
                launcher.endpoint_descriptor(endpoint, "fixture")
        for model in ("", "--exec shell", "a\n", "x" * 129):
            with self.assertRaises(launcher.Rejected):
                launcher.endpoint_descriptor("https://model.example.test/v1/chat/completions", model)

    def test_only_one_fresh_local_key(self):
        entry = {"key": "REST_API_KEY", "value": "synthetic-only", "source": "local_model_endpoint",
                 "expires_at": (NOW + datetime.timedelta(minutes=30)).isoformat()}
        document = {"schema_version": "1.0.0", "credentials": [entry]}
        self.assertEqual(launcher.read_key(document, NOW)[0], "synthetic-only")
        for field, value in (("key", "AWS_SECRET_ACCESS_KEY"), ("source", "external_read_only_grant"),
                             ("value", "a\r\n"), ("expires_at", NOW.isoformat()),
                             ("expires_at", (NOW + datetime.timedelta(hours=2)).isoformat())):
            changed = copy.deepcopy(document)
            changed["credentials"][0][field] = value
            with self.assertRaises(launcher.Rejected):
                launcher.read_key(changed, NOW)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ledger = open(Path(self.directory.name) / "requests.jsonl", "w")
        self.addCleanup(self.ledger.close)
        self.config = {"endpoint": "https://model.example.test/v1/chat/completions", "model": "fixture/model",
                       "proxy": "socks5h://172.20.0.2:1080", "deadline_seconds": 600}
        self.calls, self.responses = [], []
        def send(session, request, **kwargs):
            self.calls.append(kwargs)
            return self.responses.pop(0)
        self.transport = runner.BoundedTransport(self.config, "synthetic-only", self.ledger, send)
        self.request = types.SimpleNamespace(method="POST", url=self.config["endpoint"],
            headers={"Authorization": "Bearer synthetic-only"}, body=json.dumps({"model": "fixture/model",
                "messages": [{"role": "user", "content": "native prompt"}], "max_tokens": 150, "stream": False}).encode())
        self.kwargs = {"verify": True, "cert": None, "proxies": {"http": self.config["proxy"], "https": self.config["proxy"]}}

    def response(self, status=200, body=b'{"choices":[]}'):
        return types.SimpleNamespace(status_code=status, iter_content=lambda size: iter([body]), close=lambda: None)

    def test_transport_forces_no_redirect_and_consumes_each_retry(self):
        self.responses = [self.response(429), self.response()]
        with patch.object(runner.time, "sleep"):
            self.transport.send(None, self.request, **self.kwargs)
            self.transport.send(None, self.request, **self.kwargs)
        self.assertEqual(self.transport.attempts, 2)
        self.assertTrue(all(c["allow_redirects"] is False and c["stream"] is True and c["timeout"] <= 20 for c in self.calls))
        self.ledger.flush()
        saved = (Path(self.directory.name) / "requests.jsonl").read_text()
        self.assertNotIn("synthetic-only", saved)
        self.assertNotIn("native prompt", saved)

    def test_request_and_response_contracts_fail_before_extra_inference(self):
        for field, value in (("url", self.config["endpoint"] + "/other"), ("method", "GET"),
                             ("body", b"{}"), ("body", b"x" * 8193)):
            request = copy.deepcopy(self.request)
            setattr(request, field, value)
            with self.assertRaises(runner.BoundaryViolation):
                self.transport.send(None, request, **self.kwargs)
        for kwargs in ({**self.kwargs, "verify": False}, {**self.kwargs, "proxies": {}}):
            with self.assertRaises(runner.BoundaryViolation):
                self.transport.send(None, self.request, **kwargs)
        self.assertEqual(len(self.calls), 0)
        self.responses = [self.response(307), self.response(body=b"x" * 262145)]
        with patch.object(runner.time, "sleep"):
            for reason in ("redirect_refused", "response_size_limit"):
                with self.assertRaisesRegex(runner.BoundaryViolation, reason):
                    self.transport.send(None, self.request, **self.kwargs)

    def test_hard_attempt_byte_and_deadline_limits(self):
        for attribute, value, reason in (("attempts", 64, "inference_budget_exhausted"),
                                        ("total_bytes", 65536, "inference_budget_exhausted"),
                                        ("deadline", 0, "inference_deadline")):
            original = getattr(self.transport, attribute)
            setattr(self.transport, attribute, value)
            with self.assertRaisesRegex(runner.BoundaryViolation, reason):
                self.transport.send(None, self.request, **self.kwargs)
            setattr(self.transport, attribute, original)
        self.assertEqual(len(self.calls), 0)


if __name__ == "__main__":
    unittest.main()

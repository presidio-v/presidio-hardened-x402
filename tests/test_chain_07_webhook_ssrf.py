"""Chain 07 (MPA webhook SSRF) — POC tests demonstrating the fix blocks the attack.

Attack model: attacker injects a webhook URL pointing at an internal service
(cloud metadata, Redis, K8s API) via config manipulation. The MPA engine would
then POST the payment payload into that internal service, leaking data and/or
coercing side effects.

Fix: ``MPAApproverConfig.__post_init__`` validates scheme + IP-literal hosts
against a blocked-network allowlist. ``MPAEngine._request_single_approval``
re-resolves DNS names immediately before each request to defeat rebinding.
"""

from __future__ import annotations

import pytest

from presidio_x402.exceptions import MPAWebhookURLError
from presidio_x402.mpa import MPAApproverConfig, _ip_is_blocked, _validate_webhook_url


class TestConfigTimeValidation:
    """``_validate_webhook_url`` catches the common SSRF config shapes upfront."""

    def test_http_scheme_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="must use https"):
            _validate_webhook_url("http://approvals.example.com/cb")

    def test_file_scheme_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="must use https"):
            _validate_webhook_url("file:///etc/passwd")

    def test_empty_url_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="non-empty"):
            _validate_webhook_url("")

    def test_missing_hostname_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="hostname"):
            _validate_webhook_url("https:///path-only")

    @pytest.mark.parametrize(
        "blocked_ip",
        [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",  # AWS/GCP IMDS
            "100.64.0.1",  # CGNAT
            "0.0.0.0",  # noqa: S104 — literal used as blocklist test input, not a bind address
            "::1",
            "fc00::1",
            "fe80::1",
        ],
    )
    def test_ip_literal_in_blocked_range_refused(self, blocked_ip: str) -> None:
        url = f"https://[{blocked_ip}]/cb" if ":" in blocked_ip else f"https://{blocked_ip}/cb"
        with pytest.raises(MPAWebhookURLError, match="blocked"):
            _validate_webhook_url(url)

    def test_public_ip_literal_accepted(self) -> None:
        _validate_webhook_url("https://8.8.8.8/cb")
        _validate_webhook_url("https://1.1.1.1/cb")

    def test_public_hostname_accepted(self) -> None:
        _validate_webhook_url("https://approvals.example.com/cb")


class TestApproverConfigEnforcement:
    """``MPAApproverConfig.__post_init__`` runs the validator for webhook mode."""

    def test_webhook_mode_without_url_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="requires webhook_url"):
            MPAApproverConfig("alice", mode="webhook")

    def test_webhook_mode_with_blocked_ip_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="blocked"):
            MPAApproverConfig(
                "alice",
                mode="webhook",
                webhook_url="https://169.254.169.254/latest/meta-data/",
            )

    def test_webhook_mode_with_http_refused(self) -> None:
        with pytest.raises(MPAWebhookURLError, match="https"):
            MPAApproverConfig(
                "alice",
                mode="webhook",
                webhook_url="http://approvals.example.com/cb",
            )

    def test_crypto_mode_unaffected(self) -> None:
        # Crypto mode has no webhook_url — validator must not run.
        MPAApproverConfig("alice", mode="crypto", shared_secret=b"s")


class TestBlockedNetworkHelper:
    """``_ip_is_blocked`` covers the defence matrix."""

    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
    def test_blocked(self, ip: str) -> None:
        assert _ip_is_blocked(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public(self, ip: str) -> None:
        assert _ip_is_blocked(ip) is False

    def test_non_ip_string_returns_false(self) -> None:
        # Hostnames passed here are not blocked by this helper directly — they
        # go through the DNS-resolution check at request time instead.
        assert _ip_is_blocked("approvals.example.com") is False

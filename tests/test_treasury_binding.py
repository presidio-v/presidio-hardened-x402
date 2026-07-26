"""Treasury binding — adapter, settlement-ref@1, identity bounds, capture, CLI.

What these tests are really asserting, in one line each:

- the adapter **refuses** more than it accepts (non-verifying envelope, wrong
  signer, non-terminal verdict, out-of-bound identity string, incomplete
  settlement facts) — a bundle that exists is a bundle that verified;
- the join is *signer-bound and content-bound*: swapping either envelope, the
  decision it names, or one committed chain fact fails closed with a distinct
  reason;
- the privacy claim is the honest one — the control block is structurally
  PII-free, and the identity fields, which are **not**, are value-bounded;
- the client captures only what it actually observes on the wire, and says so.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402 import HardenedX402Client
from presidio_x402._types import PaymentDetails, PaymentResponse, SettlementReceipt
from presidio_x402.audit_log import NullAuditWriter
from presidio_x402.bindings.x402 import (
    X402Binding,
    caip2_for_network,
    parse_settlement_receipt,
)
from presidio_x402.decision_ref import (
    ControlResults,
    DecisionRefEmitter,
    build_decision_evidence,
    build_payment_decision_content,
)
from presidio_x402.treasury_binding import (
    REASON_DECISION,
    REASON_IDENTITY_BOUNDS,
    REASON_JOIN_MISMATCH,
    REASON_MALFORMED,
    REASON_NON_TERMINAL_VERDICT,
    REASON_SETTLEMENT_BAD_SIGNATURE,
    REASON_SETTLEMENT_HASH_MISMATCH,
    REASON_SIGNER_MISMATCH,
    FileSettlementWriter,
    SettlementFacts,
    TreasuryBindingError,
    check_identity_bounds,
    export_bundle,
    main,
    settlement_facts_record,
    verify_bundle,
)

SIGNER = "presidio-hardened-x402-policy"
PAY_TO = "0x00000000000000000000000000000000c0ffee00"
TX_HASH = "0x" + "ab" * 32


def _keypair() -> tuple[str, str]:
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def _facts(**overrides) -> SettlementFacts:
    kwargs = {
        "chain": "eip155:84532",
        "tx_hash": TX_HASH,
        "block_number": 19_284_411,
        "log_index": 7,
    }
    kwargs.update(overrides)
    return SettlementFacts(**kwargs)


def _content(**overrides) -> dict:
    controls = overrides.pop("controls", None) or ControlResults(
        pii_verdict="PII_REDACTED",
        pii_entities=("EMAIL_ADDRESS",),
        pii_mutated=True,
        policy_snapshot_hash="sha256:" + "11" * 32,
        replay_fingerprint_hash="sha256:" + "22" * 32,
    )
    kwargs = {
        "agent_id": "did:presidio:x402:agent-1",
        "payment_signer": PAY_TO,
        "network": "base-sepolia",
        "binding": "x402",
        "offer_hash": "sha256:" + "33" * 32,
        "details_hash": "sha256:" + "44" * 32,
        "pay_to": PAY_TO,
        "amount": "0.010000",
        "currency": "USDC",
        "resource_origin": "https://api.example.com",
        "issued_at": "2026-07-26T12:00:00.000Z",
    }
    kwargs.update(overrides)
    return build_payment_decision_content(controls=controls, **kwargs)


def _envelope(priv: str, *, signer: str = SIGNER, content: dict | None = None) -> dict:
    return build_decision_evidence(content or _content(), signing_key=priv, signer=signer)


@pytest.fixture
def bundle_fixture():
    priv, pub = _keypair()
    trust = {SIGNER: {"alg": "ed25519", "public_key": pub}}
    envelope = _envelope(priv)
    bundle = export_bundle(
        envelope,
        _facts(),
        trust_store=trust,
        signing_key=priv,
        issued_at="2026-07-26T12:00:00.000Z",
    )
    return priv, trust, envelope, bundle


# ---------------------------------------------------------------------------
# Export + verify, happy path
# ---------------------------------------------------------------------------


def test_exported_bundle_verifies_end_to_end(bundle_fixture):
    _priv, trust, decision_env, bundle = bundle_fixture
    result = verify_bundle(bundle, trust)
    assert result.ok, result.reason
    assert result.verdict == "ALLOW"
    assert result.decision_ref == decision_env["decision_ref"]
    assert result.settlement_key == f"eip155:84532|{TX_HASH}|7"
    assert result.checked == (
        "structure",
        "decision",
        "terminal",
        "identity",
        "settlement",
        "signer",
    )


def test_bundle_carries_no_key_material(bundle_fixture):
    """A bundle-supplied public key would make verification trust-on-first-use.

    The reference names the signer and the key id; the verifier resolves both
    against its *own* pinned store. Nothing in the bundle may substitute for it.
    """
    _priv, _trust, decision_env, bundle = bundle_fixture
    ref = bundle["trust_store_ref"]
    assert ref["signer"] == SIGNER
    assert "public_key" not in ref and "key" not in ref
    serialised = json.dumps(bundle)
    assert "public_key" not in serialised
    assert bundle["ingest_status"] == "treasury-ingest-pending"


def test_export_is_idempotent_for_a_fixed_issue_time(bundle_fixture):
    """Same decision + same settlement + same clock ⇒ byte-identical bundle."""
    priv, trust, decision_env, bundle = bundle_fixture
    again = export_bundle(
        decision_env,
        _facts(),
        trust_store=trust,
        signing_key=priv,
        issued_at="2026-07-26T12:00:00.000Z",
    )
    assert again["settlement_ref"] == bundle["settlement_ref"]
    assert (
        again["settlement_ref_envelope"]["settlement"]
        == bundle["settlement_ref_envelope"]["settlement"]
    )
    assert (
        again["settlement_ref_envelope"]["evidence"][0]["signature"]
        == bundle["settlement_ref_envelope"]["evidence"][0]["signature"]
    )


def test_deny_verdict_is_exportable_on_purpose(bundle_fixture):
    """A settlement that happened despite a DENY is the anomaly an auditor needs.

    Refusing to export it would hide the one case worth escalating, so DENY is
    terminal and exportable; only the interim REFER is refused.
    """
    priv, trust, decision_env, _bundle = bundle_fixture
    denied = _content(
        controls=ControlResults(
            policy_verdict="VIOLATION", policy_snapshot_hash="sha256:" + "11" * 32
        )
    )
    envelope = _envelope(priv, content=denied)
    bundle = export_bundle(envelope, _facts(), trust_store=trust, signing_key=priv)
    assert bundle["verdict"] == "DENY"
    assert verify_bundle(bundle, trust).ok


# ---------------------------------------------------------------------------
# Fail-closed refusals on the export path
# ---------------------------------------------------------------------------


def test_export_refuses_a_tampered_envelope(bundle_fixture):
    priv, trust, decision_env, _bundle = bundle_fixture
    tampered = json.loads(json.dumps(decision_env))
    tampered["payment_decision"]["payment"]["amount"] = "9999.00"
    with pytest.raises(TreasuryBindingError, match="does not verify"):
        export_bundle(tampered, _facts(), trust_store=trust, signing_key=priv)


def test_export_refuses_an_unknown_signer(bundle_fixture):
    """No trust store entry ⇒ the signature was never checked ⇒ no bundle."""
    priv, _trust, decision_env, _bundle = bundle_fixture
    with pytest.raises(TreasuryBindingError, match="does not verify"):
        export_bundle(decision_env, _facts(), trust_store={}, signing_key=priv)


def test_export_refuses_a_non_terminal_verdict(bundle_fixture):
    priv, trust, decision_env, _bundle = bundle_fixture
    referred = _content(
        controls=ControlResults(
            mpa_verdict="PENDING",
            mpa_required=True,
            policy_snapshot_hash="sha256:" + "11" * 32,
        )
    )
    envelope = _envelope(priv, content=referred)
    assert envelope["payment_decision"]["verdict"] == "REFER"
    with pytest.raises(TreasuryBindingError, match="non-terminal"):
        export_bundle(envelope, _facts(), trust_store=trust, signing_key=priv)


def test_export_refuses_to_sign_the_join_as_a_different_identity(bundle_fixture):
    """The join is the *decision signer's* assertion, not any trusted party's.

    Otherwise any trust-store member could re-point any decision at any
    transaction, which is the whole attack the signed join exists to stop.
    """
    priv, trust, decision_env, _bundle = bundle_fixture
    with pytest.raises(TreasuryBindingError, match="refusing to sign the join"):
        export_bundle(
            decision_env, _facts(), trust_store=trust, signing_key=priv, signer="someone-else"
        )


def test_export_refuses_incomplete_settlement_facts():
    """block_number/log_index are required — the receipt never carries them."""
    with pytest.raises(TreasuryBindingError, match="operator"):
        SettlementFacts.from_mapping({"chain": "eip155:8453", "tx_hash": TX_HASH})


# ---------------------------------------------------------------------------
# Identity bounds (T-TB-3) — and the honest PII claim
# ---------------------------------------------------------------------------


def test_control_block_is_structurally_pii_free(bundle_fixture):
    """Every control value is a hash, an enum label, an entity type, or a bool.

    This is the part of the record that *is* structurally PII-free, asserted by
    walking it rather than by trusting the docstring.
    """
    _priv, _trust, decision_env, _bundle = bundle_fixture
    controls = decision_env["payment_decision"]["controls"]
    enums = {
        "PII_NONE",
        "PII_WARNED",
        "PII_REDACTED",
        "PII_BLOCKED",
        "TRUSTED",
        "UNTRUSTED",
        "ALLOW",
        "VIOLATION",
        "FRESH",
        "DUPLICATE",
        "NOT_REQUIRED",
        "APPROVED",
        "PENDING",
        "TIMEOUT",
        "DENIED",
    }
    for gate, block in controls.items():
        for key, value in block.items():
            if isinstance(value, bool) or value is None:
                continue
            if key == "verdict":
                assert value in enums, (gate, value)
            elif key == "entities":
                assert all(v.replace("_", "").isalnum() for v in value), (gate, value)
            elif key.endswith("_hash"):
                assert value.startswith("sha256:") and len(value) == 71, (gate, key)
            elif key in ("threshold", "approval_refs"):
                continue  # caller strings — bounded, not structural (see below)
            else:  # pragma: no cover - a new control field must be classified here
                raise AssertionError(f"unclassified control field {gate}.{key}")


@pytest.mark.parametrize(
    ("field", "value", "why"),
    [
        ("agent_id", "a" * 257, "over the length bound"),
        ("agent_id", "agent‮evil", "bidi override (Cf)"),
        ("agent_id", "agent\x00null", "null byte (Cc)"),
        ("pay_to", "0x" + "f" * 200, "over the length bound"),
        ("resource_origin", "https://x.invalid/￹", "interlinear annotation (Cf)"),
    ],
)
def test_out_of_bound_identity_strings_are_rejected(field: str, value: str, why: str):
    """The honest half of the privacy claim: these fields exist and carry caller
    strings, so they are *bounded* rather than pretended away."""
    content = _content(**{field: value})
    with pytest.raises(TreasuryBindingError):
        check_identity_bounds(content)


def test_approval_refs_are_bounded_in_count_and_length():
    many = _content(
        controls=ControlResults(
            mpa_verdict="APPROVED",
            mpa_required=True,
            mpa_approval_refs=tuple(f"ref-{i}" for i in range(33)),
            policy_snapshot_hash="sha256:" + "11" * 32,
        )
    )
    with pytest.raises(TreasuryBindingError, match="entries"):
        check_identity_bounds(many)

    # A 513-character ref cannot be built through the emitter — decision_ref
    # already caps it at 512 — so the over-long case is assembled by hand, which
    # is exactly how it would arrive from a laxer or older producer.
    long_ref = _content()
    long_ref["controls"]["mpa"]["approval_refs"] = ["x" * 513]
    with pytest.raises(TreasuryBindingError, match="exceeds"):
        check_identity_bounds(long_ref)

    control_char = _content()
    control_char["controls"]["mpa"]["approval_refs"] = ["approval‮reversed"]
    with pytest.raises(TreasuryBindingError, match="disallowed character"):
        check_identity_bounds(control_char)


def test_empty_agent_id_is_allowed_but_empty_pay_to_is_not():
    """The pipeline emits agent_id="" when none is configured; that is a valid
    record. A missing counterparty is not."""
    check_identity_bounds(_content(agent_id=""))
    with pytest.raises(TreasuryBindingError, match="must not be empty"):
        check_identity_bounds(_content(pay_to=""))


def test_non_ascii_identity_strings_are_accepted():
    """A charset bound, not an ASCII allowlist — an international agent id is
    legitimate; a control or format character is not."""
    check_identity_bounds(_content(agent_id="агент-Ω-代理"))


def test_export_refuses_an_out_of_bound_identity_string(bundle_fixture):
    priv, trust, decision_env, _bundle = bundle_fixture
    envelope = _envelope(priv, content=_content(agent_id="a" * 300))
    with pytest.raises(TreasuryBindingError, match="exceeds"):
        export_bundle(envelope, _facts(), trust_store=trust, signing_key=priv)


# ---------------------------------------------------------------------------
# Fail-closed refusals on the verify path
# ---------------------------------------------------------------------------


def test_verify_rejects_a_swapped_join(bundle_fixture):
    """A settlement-ref naming a different decision must not ride along."""
    priv, trust, decision_env, bundle = bundle_fixture
    other = _envelope(priv, content=_content(agent_id="did:presidio:x402:agent-2"))
    other_bundle = export_bundle(other, _facts(), trust_store=trust, signing_key=priv)
    swapped = json.loads(json.dumps(bundle))
    swapped["settlement_ref_envelope"] = other_bundle["settlement_ref_envelope"]
    result = verify_bundle(swapped, trust)
    assert not result.ok and result.reason == REASON_JOIN_MISMATCH


def test_verify_rejects_a_join_signed_by_another_trusted_party(bundle_fixture):
    """Trusted is not the same as *this decision's* signer."""
    priv, trust, decision_env, bundle = bundle_fixture
    other_priv, other_pub = _keypair()
    trust_two = dict(trust)
    trust_two["other-party"] = {"alg": "ed25519", "public_key": other_pub}
    forged = json.loads(json.dumps(bundle))
    settlement = forged["settlement_ref_envelope"]
    from presidio_x402.mica import sign_evidence

    settlement["evidence"][0]["signer"] = "other-party"
    settlement["evidence"][0]["signature"] = sign_evidence(
        settlement["evidence"][0]["content_hash"], "other-party", key=other_priv
    )
    result = verify_bundle(forged, trust_two)
    assert not result.ok and result.reason == REASON_SIGNER_MISMATCH


def test_verify_reports_the_underlying_decision_reason(bundle_fixture):
    _priv, trust, decision_env, bundle = bundle_fixture
    broken = json.loads(json.dumps(bundle))
    broken["decision_ref_envelope"]["payment_decision"]["amount"] = "1"
    result = verify_bundle(broken, trust)
    assert not result.ok and result.reason == REASON_DECISION
    assert result.detail == "hash_mismatch"


def test_verify_rejects_a_tampered_settlement_signature(bundle_fixture):
    _priv, trust, decision_env, bundle = bundle_fixture
    broken = json.loads(json.dumps(bundle))
    sig = broken["settlement_ref_envelope"]["evidence"][0]["signature"]
    broken["settlement_ref_envelope"]["evidence"][0]["signature"] = ("0" * 8) + sig[8:]
    result = verify_bundle(broken, trust)
    assert not result.ok and result.reason == REASON_SETTLEMENT_BAD_SIGNATURE


def test_verify_rejects_a_mutated_settlement_fact(bundle_fixture):
    _priv, trust, decision_env, bundle = bundle_fixture
    broken = json.loads(json.dumps(bundle))
    broken["settlement_ref_envelope"]["settlement"]["settlement"]["block_number"] += 1
    result = verify_bundle(broken, trust)
    assert not result.ok and result.reason == REASON_SETTLEMENT_HASH_MISMATCH


def test_verify_rebounds_identity_on_the_read_path(bundle_fixture):
    """A bundle from an older or laxer producer still fails here.

    The read path cannot assume the writer applied the bound, so it re-applies
    it — the check is on the value, and the value travels in the bundle.
    """
    priv, trust, decision_env, _bundle = bundle_fixture
    content = _content(agent_id="a" * 300)
    envelope = build_decision_evidence(content, signing_key=priv, signer=SIGNER)
    handmade = {
        "schema": "presidio-hardened-x402/treasury-bundle@1",
        "decision_ref_envelope": envelope,
        "settlement_ref_envelope": {},
        "trust_store_ref": {"signer": SIGNER},
    }
    result = verify_bundle(handmade, trust)
    assert not result.ok and result.reason == REASON_IDENTITY_BOUNDS


def test_verify_rejects_a_non_bundle():
    assert verify_bundle({"schema": "something-else"}, {}).reason == REASON_MALFORMED
    assert verify_bundle({}, {}).reason == REASON_MALFORMED


def test_verify_rejects_a_refer_bundle_assembled_by_hand(bundle_fixture):
    priv, trust, decision_env, bundle = bundle_fixture
    referred = _content(
        controls=ControlResults(
            mpa_verdict="TIMEOUT", mpa_required=True, policy_snapshot_hash="sha256:" + "11" * 32
        )
    )
    handmade = json.loads(json.dumps(bundle))
    handmade["decision_ref_envelope"] = build_decision_evidence(
        referred, signing_key=priv, signer=SIGNER
    )
    result = verify_bundle(handmade, trust)
    assert not result.ok and result.reason == REASON_NON_TERMINAL_VERDICT


# ---------------------------------------------------------------------------
# A0 — settlement receipt capture on the client path
# ---------------------------------------------------------------------------


def _receipt_header(**overrides) -> str:
    import base64

    payload = {
        "success": True,
        "transaction": TX_HASH,
        "network": "base-sepolia",
        "payer": "0x1111111111111111111111111111111111111111",
    }
    payload.update(overrides)
    return base64.b64encode(json.dumps(payload).encode()).decode()


def test_receipt_parses_base64_and_bare_json():
    encoded = parse_settlement_receipt(_receipt_header())
    plain = parse_settlement_receipt(
        json.dumps({"success": True, "transaction": TX_HASH, "network": "base-sepolia"})
    )
    assert encoded is not None and plain is not None
    assert encoded.tx_hash == plain.tx_hash == TX_HASH
    assert encoded.chain == "eip155:84532"
    assert encoded.payer is not None and plain.payer is None


def test_receipt_is_incomplete_because_the_wire_does_not_carry_block_or_log_index():
    """The documented gap, asserted rather than assumed."""
    receipt = parse_settlement_receipt(_receipt_header())
    assert receipt is not None
    assert receipt.block_number is None and receipt.log_index is None
    assert receipt.is_complete is False
    record = settlement_facts_record(receipt, decision_ref="a" * 64)
    assert record["complete"] is False
    with pytest.raises(TreasuryBindingError, match="operator"):
        SettlementFacts.from_mapping(record)


def test_receipt_uses_volunteered_block_and_log_index_when_present():
    receipt = parse_settlement_receipt(_receipt_header(blockNumber=42, logIndex=3))
    assert receipt is not None and receipt.is_complete
    facts = SettlementFacts.from_mapping(settlement_facts_record(receipt))
    assert (facts.block_number, facts.log_index) == (42, 3)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not-base64-not-json",
        json.dumps({"success": True}),  # nothing correlatable
        json.dumps([1, 2, 3]),
        "x" * 9000,  # over the size cap
    ],
)
def test_receipt_parsing_never_raises_and_returns_none_on_junk(raw: str):
    assert parse_settlement_receipt(raw) is None


def test_receipt_records_an_unmapped_network_without_guessing_a_chain():
    """A wrong chain id would correlate a decision to a transaction on another
    chain — worse than no chain id at all."""
    receipt = parse_settlement_receipt(
        json.dumps({"transaction": TX_HASH, "network": "some-new-l2"})
    )
    assert receipt is not None
    assert receipt.network == "some-new-l2" and receipt.chain is None


def test_caip2_passthrough_and_rejection():
    assert caip2_for_network("eip155:8453") == "eip155:8453"
    assert caip2_for_network("base-sepolia") == "eip155:84532"
    assert caip2_for_network("BASE-SEPOLIA") == "eip155:84532"
    assert caip2_for_network("nope") is None
    assert caip2_for_network("") is None
    assert caip2_for_network("A" * 40) is None


def test_binding_reads_every_accepted_receipt_header_name():
    binding = X402Binding()
    for name in ("PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE", "X-PAYMENT-RECEIPT"):
        receipt = binding.settlement_receipt(httpx.Headers({name: _receipt_header()}))
        assert receipt is not None and receipt.tx_hash == TX_HASH
    assert binding.settlement_receipt(httpx.Headers({})) is None
    assert binding.settlement_receipt(object()) is None


def test_receipt_hash_binds_the_parsed_facts_to_the_bytes_received():
    header = _receipt_header()
    import hashlib

    receipt = parse_settlement_receipt(header)
    assert receipt is not None
    assert receipt.receipt_hash == "sha256:" + hashlib.sha256(header.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Gateway wiring (opt-in; default off)
# ---------------------------------------------------------------------------

_OFFER = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": "https://api.example.com/data",
                "payTo": PAY_TO,
                "requiredDeadlineSeconds": 300,
            }
        ]
    }
)


async def _mock_signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106


class _ListSettlementWriter:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def write(self, record):
        self.records.append(dict(record))


@pytest.mark.asyncio
async def test_client_captures_the_receipt_and_correlates_the_decision_ref():
    priv, pub = _keypair()
    writer = _ListSettlementWriter()
    emitter = DecisionRefEmitter(signing_key=priv, signer=SIGNER)
    with respx.mock:
        route = respx.get("https://api.example.com/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _OFFER}),
            httpx.Response(200, headers={"PAYMENT-RESPONSE": _receipt_header()}, text="paid"),
        ]
        client = HardenedX402Client(
            payment_signer=_mock_signer,
            audit_writer=NullAuditWriter(),
            decision_ref_emitter=emitter,
            settlement_writer=writer,
        )
        async with client:
            resp = await client.get("https://api.example.com/data")
    assert resp.status_code == 200
    assert len(writer.records) == 1
    record = writer.records[0]
    assert record["tx_hash"] == TX_HASH
    assert record["chain"] == "eip155:84532"
    assert isinstance(record["decision_ref"], str) and len(record["decision_ref"]) == 64
    assert record["complete"] is False
    assert pub  # keypair fixture sanity


@pytest.mark.asyncio
async def test_capture_is_off_by_default_and_never_breaks_a_payment():
    class _Exploding:
        def write(self, record):
            raise RuntimeError("sink is down")

    with respx.mock:
        route = respx.get("https://api.example.com/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _OFFER}),
            httpx.Response(200, headers={"PAYMENT-RESPONSE": _receipt_header()}, text="paid"),
        ]
        client = HardenedX402Client(
            payment_signer=_mock_signer,
            audit_writer=NullAuditWriter(),
            settlement_writer=_Exploding(),
        )
        async with client:
            resp = await client.get("https://api.example.com/data")
    assert resp.status_code == 200 and resp.text == "paid"


@pytest.mark.asyncio
async def test_no_settlement_writer_means_no_capture_work_at_all():
    with respx.mock:
        route = respx.get("https://api.example.com/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _OFFER}),
            httpx.Response(200, headers={"PAYMENT-RESPONSE": _receipt_header()}, text="paid"),
        ]
        client = HardenedX402Client(payment_signer=_mock_signer, audit_writer=NullAuditWriter())
        async with client:
            resp = await client.get("https://api.example.com/data")
    assert resp.status_code == 200


def test_file_settlement_writer_appends_json_lines(tmp_path):
    path = tmp_path / "settlements.jsonl"
    writer = FileSettlementWriter(str(path), fsync=False)
    receipt = SettlementReceipt(network="base-sepolia", chain="eip155:84532", tx_hash=TX_HASH)
    writer.write(settlement_facts_record(receipt, decision_ref="b" * 64))
    writer.write(settlement_facts_record(receipt))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["decision_ref"] == "b" * 64
    assert json.loads(lines[1])["decision_ref"] is None


# ---------------------------------------------------------------------------
# CLI round-trip
# ---------------------------------------------------------------------------


def _cli_files(tmp_path, bundle_fixture):
    priv, trust, envelope, _bundle = bundle_fixture
    (tmp_path / "env.json").write_text(json.dumps(envelope), encoding="utf-8")
    (tmp_path / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
    (tmp_path / "key").write_text(priv + "\n", encoding="utf-8")
    receipt = SettlementReceipt(network="base-sepolia", chain="eip155:84532", tx_hash=TX_HASH)
    record = settlement_facts_record(receipt, decision_ref=envelope["decision_ref"])
    record["block_number"] = 19_284_411
    record["log_index"] = 7
    (tmp_path / "settle.json").write_text(json.dumps(record), encoding="utf-8")
    return tmp_path


def test_cli_export_then_verify_round_trip(tmp_path, bundle_fixture, capsys):
    d = _cli_files(tmp_path, bundle_fixture)
    code = main(
        [
            "export",
            str(d / "env.json"),
            "--settlement",
            str(d / "settle.json"),
            "--trust",
            str(d / "trust.json"),
            "--key-file",
            str(d / "key"),
        ]
    )
    assert code == 0
    bundle_text = capsys.readouterr().out
    (d / "bundle.json").write_text(bundle_text, encoding="utf-8")

    assert main(["verify", str(d / "bundle.json"), str(d / "trust.json")]) == 0
    assert "OK" in capsys.readouterr().out


def test_cli_verify_fails_on_a_tampered_bundle(tmp_path, bundle_fixture, capsys):
    d = _cli_files(tmp_path, bundle_fixture)
    main(
        [
            "export",
            str(d / "env.json"),
            "--settlement",
            str(d / "settle.json"),
            "--trust",
            str(d / "trust.json"),
            "--key-file",
            str(d / "key"),
        ]
    )
    bundle = json.loads(capsys.readouterr().out)
    bundle["settlement_ref_envelope"]["settlement"]["settlement"]["log_index"] = 8
    (d / "bad.json").write_text(json.dumps(bundle), encoding="utf-8")
    assert main(["verify", str(d / "bad.json"), str(d / "trust.json")]) == 1
    assert "FAIL(settlement_hash_mismatch)" in capsys.readouterr().out


def test_cli_export_refuses_a_settlement_file_naming_another_decision(
    tmp_path, bundle_fixture, capsys
):
    d = _cli_files(tmp_path, bundle_fixture)
    record = json.loads((d / "settle.json").read_text(encoding="utf-8"))
    record["decision_ref"] = "c" * 64
    (d / "settle.json").write_text(json.dumps(record), encoding="utf-8")
    code = main(
        [
            "export",
            str(d / "env.json"),
            "--settlement",
            str(d / "settle.json"),
            "--trust",
            str(d / "trust.json"),
            "--key-file",
            str(d / "key"),
        ]
    )
    assert code == 1
    assert "refusing to join" in capsys.readouterr().err


def test_cli_usage_errors_exit_two(tmp_path, bundle_fixture, capsys):
    d = _cli_files(tmp_path, bundle_fixture)
    assert (
        main(
            [
                "export",
                str(d / "missing.json"),
                "--settlement",
                str(d / "settle.json"),
                "--trust",
                str(d / "trust.json"),
                "--key-file",
                str(d / "key"),
            ]
        )
        == 2
    )
    assert main(["verify", str(d / "missing.json"), str(d / "trust.json")]) == 2
    capsys.readouterr()


def test_cli_never_accepts_a_signing_key_as_an_argument():
    """A key in argv is visible in ps output to every user on the host."""
    with pytest.raises(SystemExit):
        main(["export", "e.json", "--settlement", "s.json", "--trust", "t.json", "--key", "01"])


def test_cli_export_reads_the_key_from_the_environment(
    tmp_path, bundle_fixture, capsys, monkeypatch
):
    d = _cli_files(tmp_path, bundle_fixture)
    priv = (d / "key").read_text(encoding="utf-8").strip()
    monkeypatch.setenv("PRESIDIO_X402_EVIDENCE_KEY", priv)
    code = main(
        [
            "export",
            str(d / "env.json"),
            "--settlement",
            str(d / "settle.json"),
            "--trust",
            str(d / "trust.json"),
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["schema"].endswith("treasury-bundle@1")

    monkeypatch.delenv("PRESIDIO_X402_EVIDENCE_KEY")
    assert (
        main(
            [
                "export",
                str(d / "env.json"),
                "--settlement",
                str(d / "settle.json"),
                "--trust",
                str(d / "trust.json"),
            ]
        )
        == 2
    )
    assert "no signing key" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Malformed-input surface — every shape a hostile or broken producer can send
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("envelope", "why"),
    [
        ("not-a-mapping", "not an object"),
        ({"evidence": [], "settlement": {}}, "no evidence ref"),
        ({"evidence": [{}, {}], "settlement": {}}, "two evidence refs"),
        ({"evidence": [{}], "settlement": {"schema": "wrong"}}, "wrong content schema"),
        (
            {
                "evidence": [{"content_hash": 1, "signer": "s", "signature": "x"}],
                "settlement": {"schema": "presidio-hardened-x402/settlement-ref@1"},
            },
            "non-string content hash",
        ),
    ],
)
def test_settlement_envelope_malformed_shapes_fail_closed(envelope, why: str):
    from presidio_x402.treasury_binding import verify_settlement_ref

    ok, reason, _ = verify_settlement_ref(envelope, {})
    assert not ok and reason == "settlement_malformed", why


def test_settlement_envelope_with_out_of_domain_fact_is_refused_even_when_signed(bundle_fixture):
    """A signed-but-out-of-domain integer is exactly what a sibling rejects.

    Admitting it here because "the signature checks out" would move the
    divergence downstream, where it is someone else's outage.
    """
    from presidio_x402.mica import load_trust_store, sha256_hex, sign_evidence
    from presidio_x402.treasury_binding import verify_settlement_ref

    priv, trust, _decision_env, bundle = bundle_fixture
    envelope = json.loads(json.dumps(bundle["settlement_ref_envelope"]))
    envelope["settlement"]["settlement"]["block_number"] = 2**63  # above i64::MAX
    content_hash = sha256_hex(envelope["settlement"])
    envelope["evidence"][0]["content_hash"] = content_hash
    envelope["evidence"][0]["signature"] = sign_evidence(content_hash, SIGNER, key=priv)
    ok, reason, _ = verify_settlement_ref(envelope, load_trust_store(trust))
    assert not ok and reason == "settlement_malformed"


def test_verify_rejects_an_unknown_settlement_signer(bundle_fixture):
    from presidio_x402.treasury_binding import verify_settlement_ref

    _priv, _trust, _env, bundle = bundle_fixture
    ok, reason, _ = verify_settlement_ref(bundle["settlement_ref_envelope"], {})
    assert not ok and reason == "settlement_unknown_signer"


def test_verify_rejects_a_malformed_trust_store(bundle_fixture):
    _priv, _trust, _env, bundle = bundle_fixture
    result = verify_bundle(bundle, {SIGNER: {"alg": "not-an-algorithm"}})
    assert not result.ok and result.reason == REASON_MALFORMED


def test_export_refuses_an_envelope_without_content_or_signer(bundle_fixture):
    priv, trust, decision_env, _bundle = bundle_fixture
    no_content = json.loads(json.dumps(decision_env))
    no_content["payment_decision"] = None
    with pytest.raises(TreasuryBindingError):
        export_bundle(no_content, _facts(), trust_store=trust, signing_key=priv)


def test_cli_rejects_non_object_inputs(tmp_path, bundle_fixture, capsys):
    d = _cli_files(tmp_path, bundle_fixture)
    (d / "array.json").write_text("[1, 2, 3]", encoding="utf-8")
    assert (
        main(
            [
                "export",
                str(d / "array.json"),
                "--settlement",
                str(d / "settle.json"),
                "--trust",
                str(d / "trust.json"),
                "--key-file",
                str(d / "key"),
            ]
        )
        == 2
    )
    assert main(["verify", str(d / "array.json"), str(d / "trust.json")]) == 2
    capsys.readouterr()


def test_cli_rejects_json_nested_past_the_parser(tmp_path, bundle_fixture, capsys):
    """Deep input dies at the parser, before any bound could apply — still a
    usage error, never a traceback."""
    d = _cli_files(tmp_path, bundle_fixture)
    (d / "deep.json").write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    assert main(["verify", str(d / "deep.json"), str(d / "trust.json")]) == 2
    capsys.readouterr()


def test_non_evm_transaction_ids_are_accepted_verbatim():
    """A non-eip155 chain's transaction id is not hex and is not case-folded."""
    facts = SettlementFacts(
        chain="solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ",
        tx_hash="5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV",
        block_number=1,
        log_index=0,
    )
    assert facts.tx_hash.startswith("5VER")
    with pytest.raises(TreasuryBindingError, match="bounded ASCII"):
        SettlementFacts(chain="solana:x", tx_hash="tx with spaces", block_number=1, log_index=0)

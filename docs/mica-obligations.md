# MiCA & adjacent EU obligations — research memo for the evidence module

*Research date 2026-06-12 (web-verified against primary sources). This memo is the normative source for `presidio_x402/mica.py`'s `OBLIGATION_MAP`: do not change attestation wording or article citations in code without re-checking here, and do not change this memo without re-verifying against the cited sources. Verification tags: VERIFIED-PRIMARY = read on EUR-Lex or an official EU institution/authority page; VERIFIED-SECONDARY = reputable secondary source; UNVERIFIED = flagged, not citable in product claims.*

## Framing rule (applies to every mapping)

All obligations below are addressed to the **deployer** (CASP, PPAET, financial entity, data controller) — never to this library. Evidence records attest only what the middleware observed/did on traffic routed through it. No mapping supports a claim that the middleware "complies with" or "satisfies" any article.

## 1. Timeline — the 1 July 2026 cliff

MiCA applies from 30 December 2024 (Art. 149(2)); Titles III/IV (ARTs/EMTs) from 30 June 2024 (Art. 149(3)). Title V (CASPs) and Title VI (market abuse) therefore apply since 30 Dec 2024. **VERIFIED-PRIMARY** (ESMA Interactive Single Rulebook, Art. 149).

Art. 143(3): CASPs operating lawfully before 30 Dec 2024 may continue **until 1 July 2026** or until authorisation is granted/refused, whichever is sooner; member states could shorten this. **VERIFIED-PRIMARY** (ESMA ISR, Art. 143). ESMA's statement of 17 April 2026 (ESMA75-113276571-1679): the transitional period "will officially expire across the EU on 1 July 2026"; after that, providing crypto-asset services to EU clients without a MiCA licence is a breach. **VERIFIED-PRIMARY.** Member-state variations per the official ESMA list: 6 months (LV, HU, NL, PL, SI, FI), 9 (SE), 12 (DE, IE, LT, AT, SK; EEA NO), 18/full (BG, CZ, DK, EE, GR, ES, FR, HR, IT, CY, LU, MT, RO). **VERIFIED-PRIMARY.** No amendment changing these dates was found — negative finding, **UNVERIFIED (absence-of-evidence)**; re-check before each release.

Sales consequence: after 2026-07-01 the buyer profile is *authorised* CASPs (and PPAETs) needing evidence tooling — not grandfathered entities.

## 2. CASP obligations the middleware can support

- **Art. 68(9) record-keeping (strongest hook), VERIFIED-PRIMARY:** records of "all crypto-asset services, activities, orders, and transactions", sufficient for supervision, available to clients on request, kept 5 years (7 on request). Level 2: Delegated Regulation (EU) 2025/1140 specifies record content — existence VERIFIED-PRIMARY, **field-level content not yet read**: read before claiming record-content sufficiency (we deliberately claim "component of the record set" only).
- **Art. 68(7)–(8) security, VERIFIED-PRIMARY:** delegated to DORA ("resilient and secure ICT systems as required by Regulation (EU) 2022/2554"; safeguard "availability, authenticity, integrity and confidentiality of data"). Map integrity attestations to DORA Art. 9(2) + MiCA Art. 68(8).
- **Art. 70 safekeeping:** custody/segregation arrangements — at best a supporting-control narrative; **not mapped** (too weak).
- **Art. 92(1) (Title VI), VERIFIED-PRIMARY:** "any person professionally arranging or executing transactions" (PPAET) must have arrangements to prevent/detect market abuse and report suspicions (STOR). Scope condition: assets admitted to trading (Art. 86(1)). Level 2: Delegated Regulation (EU) 2025/885 (VERIFIED-SECONDARY). Mapped as **opt-in, input-data claim only** (`ppaet` + `admitted_to_trading` flags); replay detection ≠ market-abuse detection.

## 3. TFR (EU) 2023/1113 — the redaction tension

All VERIFIED-PRIMARY (EUR-Lex CELEX 32023R1113). Applies since 30 Dec 2024 (Art. 40). Art. 14(1)–(2): originator/beneficiary name, DLT address, address/ID-number-or-DOB, LEI where available must accompany CASP transfers. Art. 14(8): the originator's CASP shall not allow initiation/execution before ensuring compliance. Art. 14(4): the information travels "in advance of, or simultaneously or concurrently with" the transfer and **need not be included in the transfer itself** (parallel secure messaging layer). Arts. 16(1)/17/19–22: beneficiary/intermediary CASP detection and missing-info procedures. Art. 26(1): 5-year retention.

**Guardrails (encoded in the module):** (1) never claim redaction satisfies or supports TFR — stripping TFR-mandated fields from a CASP messaging flow would *cause* a breach; (2) the only TFR-adjacent attestation is layer separation: redaction applies to x402 payment metadata, which is not the travel-rule messaging channel (Art. 14(4)); (3) many x402 flows (self-hosted wallet → merchant, no CASP) are outside TFR entirely — no claim at all there.

## 4. GDPR hook

Art. 5(1)(c) data minimisation + Art. 5(2) accountability ("be able to demonstrate compliance") — the signed redaction record is demonstration material for the controller. **VERIFIED-SECONDARY** (faithful full-text mirror). Supporting: Arts. 25, 32 (not quoted; UNVERIFIED wording). Caveat: minimisation is purpose-relative — data required by TFR/AML is necessary by law (see §3).

## 5. AML package — deferred

AMLR (EU) 2024/1624 applies from **10 July 2027**; AMLD6 transposition by 10 July 2027; AMLA direct supervision from 2028. **VERIFIED-SECONDARY** (dates); **article-level CASP monitoring content UNVERIFIED** (only recitals retrieved from EUR-Lex). Consequence, enforced by test: `OBLIGATION_MAP` contains **no** AMLR citations until the OJ articles are verified. Revisit ahead of 2027-07-10 — screening evidence becomes more valuable then.

## 6. DORA (EU) 2022/2554

Applies to authorised CASPs as financial entities (Art. 2(1)(f)) since **17 January 2025**. **VERIFIED-PRIMARY.** (Whether a grandfathered, not-yet-authorised CASP is caught before authorisation is an UNVERIFIED supervisory-practice nuance.) Mapped articles: **Art. 9(2)** (availability/authenticity/integrity/confidentiality of data — the audit chain's integrity property), **Art. 9(4)(c)–(d)** (access control, strong authentication — MPA, opt-in flag `mpa_enabled`), **Art. 17(2)–(3)(b)** (record/track/log/categorise ICT incidents — blocked-event logging; Art. 17 text VERIFIED-SECONDARY). Related level 2 exists (DR 2024/1772, DR 2025/301, IR 2025/302) — not mapped.

## Open items before any customer-facing use

1. Read Delegated Regulation (EU) 2025/1140 field requirements (record content) — upgrade or annotate the Art. 68(9) mapping.
2. Read Delegated Regulation (EU) 2025/885 before any PPAET-targeted sale.
3. Re-verify "no amendment to MiCA dates" (negative finding) at each release.
4. Verify AMLR article content against the OJ text before 2027 positioning.

## Primary sources

ESMA ISR MiCA Arts. 68, 70, 86, 92, 143, 149 (esma.europa.eu/publications-and-data/interactive-single-rulebook/mica/…); ESMA statement 2026-04-17 ESMA75-113276571-1679; ESMA grandfathering-periods list (Art. 143(3)); EUR-Lex CELEX 32023R1113 (TFR); EUR-Lex CELEX 32022R2554 (DORA) + ESMA DORA page; OJ L 2025/1140. Secondary: StreamLex (DORA Art. 17), gdpr-info.eu (GDPR Art. 5), CSSF/NautaDutilh (AML package dates), Regulation Tomorrow/Ganado (DR 2025/885).

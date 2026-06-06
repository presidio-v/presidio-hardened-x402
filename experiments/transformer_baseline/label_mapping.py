"""Maps Piiranha (DeBERTa-v3 PII) output labels to the x402 corpus entity_type vocabulary.

Verified against ``iiiorg/piiranha-v1-detect-personal-information`` config.id2label.
Unmapped Piiranha labels (STREET, CITY, ZIPCODE, DATEOFBIRTH, DRIVERLICENSENUM,
PASSWORD, TAXNUM, BUILDINGNUM, IDCARDNUM) are intentionally dropped: they fall
outside the six x402 evaluation entity types.
"""

from __future__ import annotations

from typing import Final

PIIRANHA_TO_X402: Final[dict[str, str]] = {
    "EMAIL": "EMAIL_ADDRESS",
    "GIVENNAME": "PERSON",
    "SURNAME": "PERSON",
    "TELEPHONENUM": "PHONE_NUMBER",
    "SOCIALNUM": "US_SSN",
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "ACCOUNTNUM": "IBAN_CODE",
}

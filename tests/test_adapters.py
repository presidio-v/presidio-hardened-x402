"""Tests for adapter stubs (langchain and crewai adapters without dependencies installed)."""

from __future__ import annotations

import pytest


class TestLangchainAdapterStub:
    """LangChain is not installed in test env — adapter should raise ImportError at init."""

    def test_import_succeeds(self):
        from presidio_x402.adapters.langchain import HardenedX402Tool

        assert HardenedX402Tool is not None

    def test_instantiation_raises_import_error_without_langchain(self):
        try:
            import langchain_core  # noqa: F401

            pytest.skip("langchain-core is installed — stub test not applicable")
        except ImportError:
            pass

        from presidio_x402.adapters.langchain import HardenedX402Tool

        with pytest.raises(ImportError, match="langchain-core"):
            HardenedX402Tool(payment_signer=None)


class TestCrewAIAdapterStub:
    """CrewAI is not installed in test env — adapter should raise ImportError at init."""

    def test_import_succeeds(self):
        from presidio_x402.adapters.crewai import HardenedX402CrewTool

        assert HardenedX402CrewTool is not None

    def test_instantiation_raises_import_error_without_crewai(self):
        try:
            import crewai  # noqa: F401

            pytest.skip("crewai is installed — stub test not applicable")
        except ImportError:
            pass

        from presidio_x402.adapters.crewai import HardenedX402CrewTool

        with pytest.raises(ImportError, match="crewai"):
            HardenedX402CrewTool(payment_signer=None)

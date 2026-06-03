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


class TestLangchainAdapterClose:
    """F-09 (2026-06-03): the adapter's aclose() must delegate to the client's
    public aclose(), not a non-existent ``_http`` attribute."""

    @pytest.mark.asyncio
    async def test_aclose_delegates_to_client_public_aclose(self):
        try:
            import langchain_core  # noqa: F401
        except ImportError:
            pytest.skip("langchain-core not installed — adapter aclose() is the stub")

        from presidio_x402.adapters.langchain import HardenedX402Tool

        closed = {"called": False}

        class _FakeClient:
            async def aclose(self) -> None:
                closed["called"] = True

        tool = HardenedX402Tool.__new__(HardenedX402Tool)
        tool._client = _FakeClient()
        await tool.aclose()
        assert closed["called"]

    def test_client_exposes_public_aclose_and_no_underscore_http(self):
        # Guards the attribute the adapter relies on, independent of langchain.
        from presidio_x402 import HardenedX402Client

        assert callable(getattr(HardenedX402Client, "aclose", None))
        assert not hasattr(HardenedX402Client, "_http")


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

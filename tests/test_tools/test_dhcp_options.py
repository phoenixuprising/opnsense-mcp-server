"""Tests for bounded dnsmasq DHCP option inspection and value updates."""

from unittest.mock import AsyncMock, call

import pytest

from opnsense_mcp.api_client import OPNsenseAPIError, WriteDisabledError
from opnsense_mcp.tools.dhcp import (
    opn_get_dnsmasq_option,
    opn_list_dnsmasq_options,
    opn_update_dnsmasq_option,
)

OPTION_UUID = "018e1462-b8f2-4a10-82f7-0179cbe81968"


@pytest.mark.parametrize("snake_case", [False, True])
@pytest.mark.parametrize("action,camel", [("search", "searchOption"), ("get", "getOption"), ("set", "setOption")])
def test_option_endpoint_variants(mock_api, snake_case, action, camel):
    mock_api._use_snake_case = snake_case
    suffix = f"{action}_option" if snake_case else camel
    assert mock_api._resolve_endpoint(f"dnsmasq.settings.{action}_option") == f"dnsmasq/settings/{suffix}"


def option_response(option_type="set"):
    return {
        "option": {
            "type": option_type,
            "option": "6",
            "option6": "",
            "interface": "lan",
            "tag": "iot",
            "force": "1",
            "value": "192.0.2.53",
            "description": "Local DNS",
        }
    }


class TestDnsmasqOptionReads:
    async def test_list_searches_options_without_write_permission(self, mock_api, mock_ctx):
        payload = {"rows": [{"uuid": OPTION_UUID}], "rowCount": 1}
        mock_api.post = AsyncMock(return_value=payload)
        assert await opn_list_dnsmasq_options(mock_ctx, search="lan", limit=20) == payload
        mock_api.post.assert_awaited_once_with(
            "dnsmasq.settings.search_option",
            {"current": 1, "rowCount": 20, "searchPhrase": "lan"},
        )

    async def test_list_caps_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": []})
        await opn_list_dnsmasq_options(mock_ctx, limit=999)
        assert mock_api.post.call_args.args[1]["rowCount"] == 500

    @pytest.mark.parametrize("limit", [0, -1])
    async def test_list_rejects_nonpositive_limit(self, mock_api, mock_ctx, limit):
        mock_api.post = AsyncMock()
        assert "error" in await opn_list_dnsmasq_options(mock_ctx, limit=limit)
        mock_api.post.assert_not_awaited()

    async def test_get_preserves_api_selection_metadata(self, mock_api, mock_ctx):
        payload = option_response({"set": {"selected": 1}, "match": {"selected": 0}})
        mock_api.get = AsyncMock(return_value=payload)
        assert await opn_get_dnsmasq_option(mock_ctx, uuid=OPTION_UUID) == payload
        mock_api.get.assert_awaited_once_with("dnsmasq.settings.get_option", path_suffix=OPTION_UUID)

    @pytest.mark.parametrize("uuid", ["", "missing", "../../core/system/halt"])
    async def test_get_rejects_invalid_uuid(self, mock_api, mock_ctx, uuid):
        mock_api.get = AsyncMock()
        assert "error" in await opn_get_dnsmasq_option(mock_ctx, uuid=uuid)
        mock_api.get.assert_not_awaited()


class TestDnsmasqOptionUpdates:
    async def test_updates_only_value_and_required_type(self, mock_api_writes, mock_ctx_writes):
        original = option_response()
        mock_api_writes.get = AsyncMock(return_value=original)
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        result = await opn_update_dnsmasq_option(
            mock_ctx_writes,
            uuid=OPTION_UUID,
            value="192.0.2.1",
            expected_value="192.0.2.53",
        )
        assert mock_api_writes.post.await_args_list == [
            call(
                "dnsmasq.settings.set_option",
                {"option": {"type": "set", "value": "192.0.2.1"}},
                path_suffix=OPTION_UUID,
            ),
            call("dnsmasq.service.reconfigure"),
        ]
        assert original == option_response()
        assert result == {"result": "saved", "uuid": OPTION_UUID, "reconfigure_status": "ok", "applied": True}
        assert cache._stale

    @pytest.mark.parametrize("selected", [1, "1", True])
    async def test_handles_selected_type_metadata(self, mock_api_writes, mock_ctx_writes, selected):
        mock_api_writes.get = AsyncMock(
            return_value=option_response(
                {
                    "set": {"value": "Set", "selected": selected},
                    "match": {"value": "Match", "selected": 0},
                }
            )
        )
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, {"status": "ok"}])
        result = await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="192.0.2.1")
        assert result["applied"]

    async def test_write_guard_runs_before_any_api_request(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock()
        mock_api.post = AsyncMock()
        with pytest.raises(WriteDisabledError):
            await opn_update_dnsmasq_option(mock_ctx, uuid=OPTION_UUID, value="192.0.2.1")
        mock_api.get.assert_not_awaited()
        mock_api.post.assert_not_awaited()

    @pytest.mark.parametrize("value", ["", "   ", "192.0.2.1\n", "192.0.2.1\r", "\x00", "\x7f"])
    async def test_rejects_empty_or_control_values(self, mock_api_writes, mock_ctx_writes, value):
        mock_api_writes.get = AsyncMock()
        mock_api_writes.post = AsyncMock()
        assert "error" in await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value=value)
        mock_api_writes.get.assert_not_awaited()
        mock_api_writes.post.assert_not_awaited()

    async def test_rejects_invalid_uuid(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock()
        mock_api_writes.post = AsyncMock()
        assert "error" in await opn_update_dnsmasq_option(mock_ctx_writes, uuid="../bad", value="192.0.2.1")
        mock_api_writes.get.assert_not_awaited()
        mock_api_writes.post.assert_not_awaited()

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"option": None},
            {"option": {}},
            option_response("match"),
            option_response({"set": {"selected": 0}, "match": {"selected": 1}}),
            option_response({"set": {"selected": 1}, "match": {"selected": 1}}),
        ],
    )
    async def test_refuses_missing_or_non_set_options(self, mock_api_writes, mock_ctx_writes, payload):
        mock_api_writes.get = AsyncMock(return_value=payload)
        mock_api_writes.post = AsyncMock()
        assert "error" in await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="192.0.2.1")
        mock_api_writes.post.assert_not_awaited()

    async def test_stale_expected_value_prevents_write(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=option_response())
        mock_api_writes.post = AsyncMock()
        result = await opn_update_dnsmasq_option(
            mock_ctx_writes,
            uuid=OPTION_UUID,
            value="192.0.2.1",
            expected_value="192.0.2.99",
        )
        assert "error" in result
        mock_api_writes.post.assert_not_awaited()

    async def test_failed_save_does_not_apply_or_invalidate(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=option_response())
        mock_api_writes.post = AsyncMock(return_value={"result": "failed", "validations": {"option.value": "Invalid"}})
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        result = await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="invalid")
        assert result["applied"] is False
        assert result["validations"] == {"option.value": "Invalid"}
        assert mock_api_writes.post.await_count == 1
        assert not cache._stale

    @pytest.mark.parametrize("response", [{"status": "failed"}, {}])
    async def test_failed_apply_does_not_report_success(self, mock_api_writes, mock_ctx_writes, response):
        mock_api_writes.get = AsyncMock(return_value=option_response())
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, response])
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        result = await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="192.0.2.1")
        assert result["result"] == "saved"
        assert result["applied"] is False
        assert "error" in result
        assert cache._stale

    async def test_apply_exception_reports_saved_state_without_exposing_details(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=option_response())
        mock_api_writes.post = AsyncMock(side_effect=[{"result": "saved"}, OPNsenseAPIError("private-details")])
        cache = mock_ctx_writes.lifespan_context["config_cache"]
        cache._stale = False
        result = await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="192.0.2.1")
        assert result["result"] == "saved"
        assert result["applied"] is False
        assert result["reconfigure_status"] == "unknown"
        assert "error" in result
        assert "private-details" not in str(result)
        assert cache._stale

    async def test_save_exception_does_not_apply(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value=option_response())
        mock_api_writes.post = AsyncMock(side_effect=OPNsenseAPIError("Unavailable"))
        with pytest.raises(OPNsenseAPIError):
            await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="192.0.2.1")
        assert mock_api_writes.post.await_count == 1

    async def test_api_exception_before_save_does_not_apply(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(side_effect=OPNsenseAPIError("Unavailable"))
        mock_api_writes.post = AsyncMock()
        with pytest.raises(OPNsenseAPIError):
            await opn_update_dnsmasq_option(mock_ctx_writes, uuid=OPTION_UUID, value="192.0.2.1")
        mock_api_writes.post.assert_not_awaited()

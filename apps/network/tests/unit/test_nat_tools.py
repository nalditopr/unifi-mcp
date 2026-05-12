"""Tests for the NAT-rule MCP tools (apps/network/src/unifi_network_mcp/tools/nat.py).

Covers the full tool surface — list/get/toggle/create/update/delete — and
exercises both the preview and confirm branches plus the local validation
that rejects bad input before reaching the controller.

All controller-facing calls are stubbed via AsyncMock on the shared
``firewall_manager`` singleton; no real network or controller is touched.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("UNIFI_HOST", "127.0.0.1")
os.environ.setdefault("UNIFI_USERNAME", "test")
os.environ.setdefault("UNIFI_PASSWORD", "test")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DNAT_RULE = {
    "_id": "rule_dnat_001",
    "description": "NTP - Fireflies",
    "enabled": True,
    "type": "DNAT",
    "ip_version": "IPV4",
    "ip_address": "192.168.98.85",
    "in_interface": "iface_fireflies",
    "out_interface": None,
    "protocol": "udp",
    "port": "123",
    "exclude": False,
    "logging": True,
    "rule_index": 0,
    "setting_preference": "manual",
    "is_predefined": False,
    "source_filter": {"filter_type": "NONE"},
    "destination_filter": {
        "filter_type": "ADDRESS_AND_PORT",
        "address": "0.0.0.0/0",
        "port": "123",
        "firewall_group_ids": [],
        "invert_address": False,
        "invert_port": False,
    },
}

SNAT_RULE = {
    "_id": "rule_snat_001",
    "description": "VPN out via ATT",
    "enabled": True,
    "type": "SNAT",
    "ip_version": "IPV4",
    "ip_address": "203.0.113.73",
    "in_interface": None,
    "out_interface": "iface_wan_att",
    "protocol": "all",
    "port": None,
    "exclude": False,
    "logging": False,
    "rule_index": 7,
    "setting_preference": "manual",
    "is_predefined": False,
    "source_filter": {
        "filter_type": "NETWORK_CONF",
        "firewall_group_ids": ["grp_vpn"],
    },
    "destination_filter": {"filter_type": "NONE"},
}


def _patch_fm():
    """Patch the module-level firewall_manager symbol that tools/nat.py imports."""
    return patch("unifi_network_mcp.tools.nat.firewall_manager")


# ---------------------------------------------------------------------------
# list_nat_rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_nat_rules_success():
    """Happy path: returns summarised rules with site + count."""
    with _patch_fm() as fm:
        fm.get_nat_rules = AsyncMock(return_value=[DNAT_RULE, SNAT_RULE])
        fm._connection = MagicMock(site="default")

        from unifi_network_mcp.tools.nat import list_nat_rules

        result = await list_nat_rules(include_predefined=False)

    assert result["success"] is True
    assert result["site"] == "default"
    assert result["count"] == 2
    assert result["include_predefined"] is False

    # Summarised, not raw — `_id` is renamed to `id`
    ids = {r["id"] for r in result["nat_rules"]}
    assert ids == {"rule_dnat_001", "rule_snat_001"}

    # DNS-catch style filter.port should survive the summary (regression guard
    # for the port-omission bug fixed during initial live testing).
    dnat = next(r for r in result["nat_rules"] if r["id"] == "rule_dnat_001")
    assert dnat["destination_filter"]["port"] == "123"

    # NETWORK_CONF filter_type passes through cleanly.
    snat = next(r for r in result["nat_rules"] if r["id"] == "rule_snat_001")
    assert snat["source_filter"]["filter_type"] == "NETWORK_CONF"


@pytest.mark.asyncio
async def test_list_nat_rules_error_returns_shape():
    """Manager error is caught and surfaced as success=False, not a raise."""
    with _patch_fm() as fm:
        fm.get_nat_rules = AsyncMock(side_effect=RuntimeError("boom"))
        fm._connection = MagicMock(site="default")

        from unifi_network_mcp.tools.nat import list_nat_rules

        result = await list_nat_rules()

    assert result["success"] is False
    assert "boom" in result["error"]


# ---------------------------------------------------------------------------
# get_nat_rule_details
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_nat_rule_details_found():
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)

        from unifi_network_mcp.tools.nat import get_nat_rule_details

        result = await get_nat_rule_details(rule_id="rule_dnat_001")

    assert result == {
        "success": True,
        "rule_id": "rule_dnat_001",
        "details": DNAT_RULE,
    }


@pytest.mark.asyncio
async def test_get_nat_rule_details_not_found():
    from unifi_core.exceptions import UniFiNotFoundError

    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(
            side_effect=UniFiNotFoundError("nat_rule", "missing")
        )

        from unifi_network_mcp.tools.nat import get_nat_rule_details

        result = await get_nat_rule_details(rule_id="missing")

    assert result["success"] is False
    assert "missing" in result["error"]


# ---------------------------------------------------------------------------
# toggle_nat_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_toggle_nat_rule_preview_does_not_call_manager():
    """Preview (confirm=false) must not mutate the controller."""
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.toggle_nat_rule = AsyncMock(return_value=True)

        from unifi_network_mcp.tools.nat import toggle_nat_rule

        result = await toggle_nat_rule(rule_id="rule_dnat_001", confirm=False)

    fm.toggle_nat_rule.assert_not_awaited()
    # preview_response/toggle_preview output uses `action` key.
    assert result.get("action") == "toggle"
    assert result.get("resource_type") == "nat_rule"


@pytest.mark.asyncio
async def test_toggle_nat_rule_confirm_calls_manager():
    """With confirm=true the manager flip is invoked exactly once."""
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.toggle_nat_rule = AsyncMock(return_value=True)

        from unifi_network_mcp.tools.nat import toggle_nat_rule

        result = await toggle_nat_rule(rule_id="rule_dnat_001", confirm=True)

    fm.toggle_nat_rule.assert_awaited_once_with("rule_dnat_001")
    assert result == {
        "success": True,
        "rule_id": "rule_dnat_001",
        "description": "NTP - Fireflies",
        "enabled": False,  # DNAT_RULE.enabled was True; flip to False
    }


# ---------------------------------------------------------------------------
# create_nat_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_nat_rule_rejects_missing_type():
    """type is required and must be SNAT or DNAT."""
    with _patch_fm() as fm:
        fm.create_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import create_nat_rule

        result = await create_nat_rule(rule={"description": "x"}, confirm=True)

    fm.create_nat_rule.assert_not_awaited()
    assert result["success"] is False
    assert "SNAT" in result["error"]


@pytest.mark.asyncio
async def test_create_nat_rule_rejects_invalid_type():
    with _patch_fm() as fm:
        fm.create_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import create_nat_rule

        result = await create_nat_rule(
            rule={"type": "MASQUERADE", "description": "x"}, confirm=True
        )

    fm.create_nat_rule.assert_not_awaited()
    assert result["success"] is False


@pytest.mark.asyncio
async def test_create_nat_rule_rejects_missing_description():
    with _patch_fm() as fm:
        fm.create_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import create_nat_rule

        result = await create_nat_rule(rule={"type": "DNAT"}, confirm=True)

    fm.create_nat_rule.assert_not_awaited()
    assert result["success"] is False
    assert "description" in result["error"]


@pytest.mark.asyncio
async def test_create_nat_rule_preview_applies_defaults_but_does_not_call_manager():
    """Preview fills in default fields (enabled, exclude, etc.) for visibility."""
    payload = {"type": "DNAT", "description": "test"}
    with _patch_fm() as fm:
        fm.create_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import create_nat_rule

        result = await create_nat_rule(rule=payload, confirm=False)

    fm.create_nat_rule.assert_not_awaited()
    assert result["success"] is True
    assert result["preview"] is True
    assert result["action"] == "create"
    assert result["would_create"]["enabled"] is True
    assert result["would_create"]["exclude"] is False
    assert result["would_create"]["logging"] is False
    assert result["would_create"]["ip_version"] == "IPV4"


@pytest.mark.asyncio
async def test_create_nat_rule_confirm_calls_manager_with_defaulted_payload():
    payload = {"type": "DNAT", "description": "test"}
    created = {**payload, "_id": "rule_new_001", "enabled": True}
    with _patch_fm() as fm:
        fm.create_nat_rule = AsyncMock(return_value=created)

        from unifi_network_mcp.tools.nat import create_nat_rule

        result = await create_nat_rule(rule=payload, confirm=True)

    fm.create_nat_rule.assert_awaited_once()
    sent_payload = fm.create_nat_rule.await_args.args[0]
    # Defaults applied client-side before sending.
    assert sent_payload["enabled"] is True
    assert sent_payload["exclude"] is False
    assert sent_payload["ip_version"] == "IPV4"

    assert result["success"] is True
    assert result["rule_id"] == "rule_new_001"


# ---------------------------------------------------------------------------
# update_nat_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_nat_rule_rejects_unknown_field():
    """Unknown update fields must be rejected, not silently merged in."""
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.update_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import update_nat_rule

        result = await update_nat_rule(
            rule_id="rule_dnat_001",
            updates={"definitely_not_a_field": "x"},
            confirm=True,
        )

    fm.update_nat_rule.assert_not_awaited()
    assert result["success"] is False
    assert "definitely_not_a_field" in result["error"]


@pytest.mark.asyncio
async def test_update_nat_rule_preview_does_not_call_manager():
    """Preview path must not mutate."""
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.update_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import update_nat_rule

        result = await update_nat_rule(
            rule_id="rule_dnat_001",
            updates={"description": "renamed"},
            confirm=False,
        )

    fm.update_nat_rule.assert_not_awaited()
    assert result.get("action") == "update"
    assert result.get("resource_type") == "nat_rule"


@pytest.mark.asyncio
async def test_update_nat_rule_confirm_passes_updates_through():
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.update_nat_rule = AsyncMock(return_value=True)

        from unifi_network_mcp.tools.nat import update_nat_rule

        updates = {"description": "renamed", "logging": False}
        result = await update_nat_rule(
            rule_id="rule_dnat_001", updates=updates, confirm=True
        )

    fm.update_nat_rule.assert_awaited_once_with("rule_dnat_001", updates)
    assert result["success"] is True
    assert result["rule_id"] == "rule_dnat_001"


@pytest.mark.asyncio
async def test_update_nat_rule_rejects_empty_updates():
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.update_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import update_nat_rule

        result = await update_nat_rule(
            rule_id="rule_dnat_001", updates={}, confirm=True
        )

    fm.update_nat_rule.assert_not_awaited()
    assert result["success"] is False


# ---------------------------------------------------------------------------
# delete_nat_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_nat_rule_preview_does_not_call_manager():
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.delete_nat_rule = AsyncMock()

        from unifi_network_mcp.tools.nat import delete_nat_rule

        result = await delete_nat_rule(rule_id="rule_dnat_001", confirm=False)

    fm.delete_nat_rule.assert_not_awaited()
    assert result["preview"] is True
    assert result["action"] == "delete"
    assert result["would_delete"]["id"] == "rule_dnat_001"


@pytest.mark.asyncio
async def test_delete_nat_rule_confirm_calls_manager():
    with _patch_fm() as fm:
        fm.get_nat_rule_by_id = AsyncMock(return_value=DNAT_RULE)
        fm.delete_nat_rule = AsyncMock(return_value=True)

        from unifi_network_mcp.tools.nat import delete_nat_rule

        result = await delete_nat_rule(rule_id="rule_dnat_001", confirm=True)

    fm.delete_nat_rule.assert_awaited_once_with("rule_dnat_001")
    assert result["success"] is True

"""NAT rule tools for the Unifi Network MCP server.

Wraps the V2 NAT endpoint exposed by UniFi Network controllers. A single
resource type (`/nat`) covers:

- SNAT       (`type=SNAT` + `out_interface`)
- DNAT       (`type=DNAT` + `ip_address`)
- 1:1 NAT    (paired SNAT + DNAT rules with matching `ip_address`)
- No-NAT     (`exclude=true`)

Hairpin NAT is *not* a NAT-rule resource — it is a per-port-forward boolean,
handled by the port_forwards tools.

Filter shape (`source_filter` / `destination_filter`):
    {
        "filter_type": NONE | ADDRESS | PORT | ADDRESS_AND_PORT | NETWORK_CONF,
        "address": "<cidr>",                       # ADDRESS/ADDRESS_AND_PORT
        "port": "<port-or-range>",                 # PORT/ADDRESS_AND_PORT
        "firewall_group_ids": ["<group-id>", ...], # NETWORK_CONF + group refs
        "invert_address": bool,
        "invert_port": bool,
    }

`NETWORK_CONF` selects the networks listed in `firewall_group_ids` rather
than a CIDR — used by SNAT rules that source-translate a VLAN to a WAN IP.
"""

import logging
from typing import Annotated, Any, Dict

from mcp.types import ToolAnnotations
from pydantic import Field

from unifi_core.confirmation import toggle_preview, update_preview
from unifi_core.exceptions import UniFiNotFoundError
from unifi_network_mcp.runtime import firewall_manager, server

logger = logging.getLogger(__name__)


def _summarize_filter(f: Any) -> Dict[str, Any]:
    """Lift the most useful fields out of a NAT filter dict for list summaries."""
    if not isinstance(f, dict):
        return {}
    return {
        "filter_type": f.get("filter_type"),
        "address": f.get("address"),
        "port": f.get("port"),
        "firewall_group_ids": f.get("firewall_group_ids"),
        "invert_address": f.get("invert_address"),
        "invert_port": f.get("invert_port"),
    }


def _summarize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Trim a raw NAT rule down to the fields most callers care about."""
    return {
        "id": rule.get("_id"),
        "description": rule.get("description"),
        "enabled": rule.get("enabled"),
        "type": rule.get("type"),
        "ip_version": rule.get("ip_version"),
        "ip_address": rule.get("ip_address"),
        "in_interface": rule.get("in_interface"),
        "out_interface": rule.get("out_interface"),
        "protocol": rule.get("protocol"),
        "port": rule.get("port"),
        "exclude": rule.get("exclude"),
        "logging": rule.get("logging"),
        "rule_index": rule.get("rule_index"),
        "setting_preference": rule.get("setting_preference"),
        "is_predefined": rule.get("is_predefined"),
        "source_filter": _summarize_filter(rule.get("source_filter")),
        "destination_filter": _summarize_filter(rule.get("destination_filter")),
    }


@server.tool(
    name="unifi_list_nat_rules",
    description=(
        "List NAT rules (SNAT, DNAT, 1:1 NAT, NAT exceptions) on your "
        "Unifi Network controller. System / predefined rules are excluded by "
        "default."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_nat_rules(
    include_predefined: Annotated[
        bool,
        Field(
            default=False,
            description=(
                "Include system-defined NAT rules. False (default) returns "
                "only user-configurable rules."
            ),
        ),
    ] = False,
) -> Dict[str, Any]:
    """Return all NAT rules visible to the controller.

    Each entry is summarised to the fields most callers care about; use
    `unifi_get_nat_rule_details` for the full raw payload.
    """
    try:
        rules = await firewall_manager.get_nat_rules(include_predefined=include_predefined)
        return {
            "success": True,
            "site": firewall_manager._connection.site,
            "count": len(rules),
            "include_predefined": include_predefined,
            "nat_rules": [_summarize_rule(r) for r in rules if isinstance(r, dict)],
        }
    except Exception as e:
        logger.error("Error listing NAT rules: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list NAT rules: {e}"}


@server.tool(
    name="unifi_get_nat_rule_details",
    description="Get the full raw configuration of a NAT rule by its ID.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_nat_rule_details(
    rule_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the NAT rule (from unifi_list_nat_rules)"),
    ],
) -> Dict[str, Any]:
    """Return the raw NAT rule dict for the given ID."""
    try:
        rule = await firewall_manager.get_nat_rule_by_id(rule_id)
        return {"success": True, "rule_id": rule_id, "details": rule}
    except UniFiNotFoundError:
        return {"success": False, "error": f"NAT rule {rule_id} not found"}
    except Exception as e:
        logger.error("Error getting NAT rule %s: %s", rule_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get NAT rule: {e}"}


@server.tool(
    name="unifi_toggle_nat_rule",
    description=(
        "Toggle a NAT rule's enabled state on or off. Returns a preview "
        "unless confirm=true."
    ),
    annotations=ToolAnnotations(destructiveHint=False, idempotentHint=False, openWorldHint=False),
)
async def toggle_nat_rule(
    rule_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the NAT rule to toggle (from unifi_list_nat_rules)"),
    ],
    confirm: Annotated[
        bool,
        Field(
            default=False,
            description="When true, executes the toggle. When false (default), returns a preview of the changes.",
        ),
    ] = False,
) -> Dict[str, Any]:
    """Flip the `enabled` flag on a NAT rule, with a preview-first guard."""
    try:
        existing = await firewall_manager.get_nat_rule_by_id(rule_id)
        current_state = bool(existing.get("enabled", False))
        new_state = not current_state
        rule_name = existing.get("description") or rule_id

        if not confirm:
            return toggle_preview(
                resource_type="nat_rule",
                resource_id=rule_id,
                resource_name=rule_name,
                current_enabled=current_state,
            )

        ok = await firewall_manager.toggle_nat_rule(rule_id)
        return {
            "success": ok,
            "rule_id": rule_id,
            "description": rule_name,
            "enabled": new_state if ok else current_state,
        }
    except UniFiNotFoundError:
        return {"success": False, "error": f"NAT rule {rule_id} not found"}
    except Exception as e:
        logger.error("Error toggling NAT rule %s: %s", rule_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to toggle NAT rule: {e}"}


@server.tool(
    name="unifi_create_nat_rule",
    description=(
        "Create a NAT rule (SNAT, DNAT, or NAT exception) on your Unifi "
        "Network controller. Required: type (SNAT|DNAT), description. "
        "Common optional fields: ip_address (translation target), in_interface "
        "(DNAT incoming iface ID), out_interface (SNAT egress iface ID), "
        "protocol (udp|tcp|tcp_udp|all), port (top-level port mirror), "
        "ip_version (IPV4|IPV6, default IPV4), enabled (default true), "
        "exclude (no-NAT flag, default false), logging, rule_index, "
        "setting_preference (auto|manual), pppoe_use_base_interface, "
        "source_filter, destination_filter. Filter shape: "
        "{filter_type: NONE|ADDRESS|PORT|ADDRESS_AND_PORT|NETWORK_CONF, "
        "address, port, firewall_group_ids, invert_address, invert_port}. "
        "NETWORK_CONF targets the matching networks via firewall_group_ids."
    ),
    annotations=ToolAnnotations(destructiveHint=False, idempotentHint=False, openWorldHint=False),
)
async def create_nat_rule(
    rule: Annotated[
        Dict[str, Any],
        Field(
            description=(
                "NAT rule configuration dict. Required: type (SNAT|DNAT), description. "
                "See tool description for the full field reference."
            )
        ),
    ],
    confirm: Annotated[
        bool,
        Field(
            default=False,
            description="When true, creates the rule. When false (default), returns a preview of the changes.",
        ),
    ] = False,
) -> Dict[str, Any]:
    """Create a NAT rule. Validates `type` + `description` locally before sending.

    Canonical DNAT redirect (NTP catch-all) shape, captured from the Network UI:
        {
            "description": "NTP - Fireflies",
            "type": "DNAT",
            "ip_version": "IPV4",
            "ip_address": "192.168.98.85",
            "in_interface": "<network-id>",
            "protocol": "udp",
            "port": "123",
            "source_filter": {"filter_type": "NONE"},
            "destination_filter": {
                "filter_type": "ADDRESS_AND_PORT",
                "address": "0.0.0.0/0",
                "port": "123",
                "invert_address": false,
                "invert_port": false,
            },
            "enabled": true,
            "logging": true,
            "exclude": false,
            "pppoe_use_base_interface": false,
            "setting_preference": "manual",
            "rule_index": 8,
        }

    Notes for callers:
    - `port` is a **string**, even when single-port — controller rejects ints.
    - `source_filter` must be present; use `{"filter_type": "NONE"}` for "any".
    - Omit `_id` on create; the controller assigns one.
    """
    try:
        if not isinstance(rule, dict):
            return {"success": False, "error": "rule must be a dict"}
        if rule.get("type") not in ("SNAT", "DNAT"):
            return {"success": False, "error": "rule.type must be 'SNAT' or 'DNAT'"}
        if not rule.get("description"):
            return {"success": False, "error": "rule.description is required"}

        payload = dict(rule)
        payload.setdefault("enabled", True)
        payload.setdefault("exclude", False)
        payload.setdefault("logging", False)
        payload.setdefault("ip_version", "IPV4")

        if not confirm:
            return {
                "success": True,
                "preview": True,
                "action": "create",
                "resource_type": "nat_rule",
                "would_create": payload,
            }

        created = await firewall_manager.create_nat_rule(payload)
        if created is None:
            return {"success": False, "error": "Controller did not return a created rule"}
        return {
            "success": True,
            "rule_id": created.get("_id"),
            "details": created,
        }
    except Exception as e:
        logger.error("Error creating NAT rule: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to create NAT rule: {e}"}


@server.tool(
    name="unifi_update_nat_rule",
    description=(
        "Update specific fields of an existing NAT rule. Returns a preview "
        "unless confirm=true. Allowed fields: description, enabled, exclude, "
        "logging, ip_version, type, ip_address, out_interface, rule_index, "
        "source_filter, destination_filter. Nested filter dicts are merged, so "
        "you can patch a single sub-field."
    ),
    annotations=ToolAnnotations(destructiveHint=False, idempotentHint=False, openWorldHint=False),
)
async def update_nat_rule(
    rule_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the NAT rule to update (from unifi_list_nat_rules)"),
    ],
    updates: Annotated[
        Dict[str, Any],
        Field(description="Dictionary of fields to update. See tool description for allowed keys."),
    ],
    confirm: Annotated[
        bool,
        Field(
            default=False,
            description="When true, applies the update. When false (default), returns a preview of the changes.",
        ),
    ] = False,
) -> Dict[str, Any]:
    """Partial-update a NAT rule with a preview-first guard."""
    try:
        if not isinstance(updates, dict) or not updates:
            return {"success": False, "error": "updates must be a non-empty dict"}

        existing = await firewall_manager.get_nat_rule_by_id(rule_id)
        rule_name = existing.get("description") or rule_id

        # Reject unknown fields rather than silently merging them.
        allowed = {
            "description",
            "enabled",
            "exclude",
            "logging",
            "ip_version",
            "type",
            "ip_address",
            "in_interface",
            "out_interface",
            "protocol",
            "port",
            "rule_index",
            "setting_preference",
            "pppoe_use_base_interface",
            "source_filter",
            "destination_filter",
        }
        unknown = sorted(set(updates) - allowed)
        if unknown:
            return {"success": False, "error": f"Unknown update fields: {unknown}"}

        if not confirm:
            return update_preview(
                resource_type="nat_rule",
                resource_id=rule_id,
                resource_name=rule_name,
                current_state=existing,
                updates=updates,
            )

        ok = await firewall_manager.update_nat_rule(rule_id, updates)
        return {"success": ok, "rule_id": rule_id, "description": rule_name}
    except UniFiNotFoundError:
        return {"success": False, "error": f"NAT rule {rule_id} not found"}
    except Exception as e:
        logger.error("Error updating NAT rule %s: %s", rule_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update NAT rule: {e}"}


@server.tool(
    name="unifi_delete_nat_rule",
    description="Delete a NAT rule by ID. Returns a preview unless confirm=true.",
    annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False, openWorldHint=False),
)
async def delete_nat_rule(
    rule_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the NAT rule to delete (from unifi_list_nat_rules)"),
    ],
    confirm: Annotated[
        bool,
        Field(
            default=False,
            description="When true, deletes the rule. When false (default), returns a preview of the change.",
        ),
    ] = False,
) -> Dict[str, Any]:
    """Delete a NAT rule. Preview-first."""
    try:
        existing = await firewall_manager.get_nat_rule_by_id(rule_id)
        rule_name = existing.get("description") or rule_id

        if not confirm:
            return {
                "success": True,
                "preview": True,
                "action": "delete",
                "resource_type": "nat_rule",
                "resource_id": rule_id,
                "resource_name": rule_name,
                "would_delete": _summarize_rule(existing),
            }

        ok = await firewall_manager.delete_nat_rule(rule_id)
        return {"success": ok, "rule_id": rule_id, "description": rule_name}
    except UniFiNotFoundError:
        return {"success": False, "error": f"NAT rule {rule_id} not found"}
    except Exception as e:
        logger.error("Error deleting NAT rule %s: %s", rule_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to delete NAT rule: {e}"}

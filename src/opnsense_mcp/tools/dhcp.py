"""DHCP tools — ISC, Kea, and dnsmasq leases, ranges, and options."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.server import get_api, get_config_cache, mcp


@mcp.tool()
async def opn_list_dhcp_leases(ctx: Context) -> dict[str, Any]:
    """List current DHCPv4 leases from the ISC DHCP server (legacy).

    Use this when the OPNsense instance uses the ISC DHCP plugin (os-isc-dhcp).
    ISC DHCP is legacy and being phased out — most 26.x instances use dnsmasq or Kea.
    Use opn_scan_config first to check which DHCP backend is active.
    Returns: dict with DHCP lease entries including address, mac, and
    hostname fields. (If the API answers with a bare array, it arrives
    wrapped in the 'rows'/'rowCount' envelope.)
    """
    api = get_api(ctx)
    return await api.get("dhcpv4.leases.search")


@mcp.tool()
async def opn_list_kea_leases(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List current DHCPv4 leases from the Kea DHCP server.

    Use this when the OPNsense instance uses Kea for DHCP (available since 24.7).
    Kea is the modern replacement for ISC DHCP, recommended for HA setups.
    Use opn_scan_config first to check which DHCP backend is active.
    Returns: dict with 'rows' (list of leases) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "kea.leases4.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_list_dnsmasq_leases(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List current DHCPv4 and DHCPv6 leases from the dnsmasq DNS/DHCP server.

    Use this when the OPNsense instance uses dnsmasq for DHCP (default in 26.x).
    dnsmasq is a lightweight combined DNS/DHCP server that handles both
    DHCPv4 and DHCPv6. IPv6 leases appear alongside IPv4 leases in the results.
    Use opn_scan_config first to check which DHCP backend is active.
    Returns: dict with 'rows' (list of leases) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "dnsmasq.leases.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


def _option_uuid(value: str) -> str | None:
    try:
        return str(UUID(value))
    except ValueError:
        return None


@mcp.tool()
async def opn_list_dnsmasq_options(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List dnsmasq DHCPv4/DHCPv6 options and their UUIDs.

    Use this to find advertised DNS servers (DHCPv4 option 6 or DHCPv6
    option 23), gateways, and interface/tag-scoped options before editing.
    Search results may contain display labels; use opn_get_dnsmasq_option
    for the full option definition. Limit must be positive and is capped at 500.
    Returns: dict with 'rows' and 'rowCount'.
    """
    if limit <= 0:
        return {"error": "limit must be positive"}
    return await get_api(ctx).post(
        "dnsmasq.settings.search_option",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_get_dnsmasq_option(ctx: Context, uuid: str) -> dict[str, Any]:
    """Get an existing dnsmasq DHCP option by UUID without changing it.

    Use opn_list_dnsmasq_options to find its UUID. The 'option' object
    includes type, DHCPv4/DHCPv6 option codes, value, interface, tags,
    force flag, and description. Select fields may use selected-item maps.
    """
    canonical_uuid = _option_uuid(uuid)
    if canonical_uuid is None:
        return {"error": "uuid must be a valid DHCP option UUID"}
    return await get_api(ctx).get("dnsmasq.settings.get_option", path_suffix=canonical_uuid)


@mcp.tool()
async def opn_update_dnsmasq_option(
    ctx: Context,
    uuid: str,
    value: str,
    expected_value: str | None = None,
) -> dict[str, Any]:
    """Update only an existing dnsmasq DHCP set-option's value and apply.

    Use this to change advertised DNS servers, including a later Pi-hole
    cutover, without changing the option code, interface, tags, force flag,
    or description. DHCP match rules are deliberately unsupported.
    First inspect with opn_list_dnsmasq_options and opn_get_dnsmasq_option.
    Optionally supply expected_value to refuse an update if the current
    value differs; this is a preflight check, not an atomic compare-and-swap.

    Requires OPNSENSE_ALLOW_WRITES=true. A successful save reconfigures
    dnsmasq immediately; existing clients need a DHCP renewal. There is no
    automatic rollback. If applying fails, the saved change remains pending.
    Returns: result, uuid, reconfigure_status, and applied; failures include error.
    """
    api = get_api(ctx)
    api.require_writes()
    canonical_uuid = _option_uuid(uuid)
    if canonical_uuid is None:
        return {"error": "uuid must be a valid DHCP option UUID"}
    if not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return {"error": "value must be nonempty and contain no control characters"}

    current = await api.get("dnsmasq.settings.get_option", path_suffix=canonical_uuid)
    option = current.get("option")
    if not isinstance(option, dict):
        return {"error": "DHCP option not found or response is invalid", "uuid": canonical_uuid}
    option_type = option.get("type")
    if isinstance(option_type, dict):
        selected = [
            key for key, item in option_type.items() if isinstance(item, dict) and item.get("selected") in (1, "1")
        ]
        option_type = selected[0] if len(selected) == 1 else None
    if option_type != "set":
        return {"error": "Only existing DHCP set options can be updated", "uuid": canonical_uuid}
    if expected_value is not None and option.get("value") != expected_value:
        return {"error": "Current value differs from expected_value; inspect before retrying", "uuid": canonical_uuid}

    result = await api.post(
        "dnsmasq.settings.set_option",
        {"option": {"type": "set", "value": value}},
        path_suffix=canonical_uuid,
    )
    if result.get("result") != "saved":
        return {**result, "uuid": canonical_uuid, "applied": False, "error": "DHCP option was not saved"}

    get_config_cache(ctx).invalidate()
    try:
        reconfigure_result = await api.post("dnsmasq.service.reconfigure")
    except OPNsenseAPIError:
        return {
            "result": "saved",
            "uuid": canonical_uuid,
            "applied": False,
            "reconfigure_status": "unknown",
            "error": "DHCP option saved but applying failed; inspect dnsmasq status before retrying",
        }
    status = reconfigure_result.get("status", "unknown")
    response: dict[str, Any] = {
        "result": "saved",
        "uuid": canonical_uuid,
        "reconfigure_status": status,
        "applied": status == "ok",
    }
    if not response["applied"]:
        response["error"] = "DHCP option saved but dnsmasq reconfiguration did not succeed; change remains pending"
    return response


# --- Dnsmasq DHCP Range Management ---


@mcp.tool()
async def opn_list_dnsmasq_ranges(
    ctx: Context,
    search: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List dnsmasq DHCP ranges (both DHCPv4 and DHCPv6 with RA config).

    Use this to see configured DHCP address pools and Router Advertisement
    settings for each interface. Both IPv4 and IPv6 ranges appear in the
    same list.

    Key fields: interface, start_addr, end_addr, prefix_len (IPv6) or
    subnet_mask (IPv4), ra_mode (slaac/ra-stateless/ra-only),
    ra_priority, lease_time, enabled.

    Note: Requires the dnsmasq DNS/DHCP server (os-dnsmasq-dns or built-in).
    Returns: dict with 'rows' (list of ranges) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "dnsmasq.settings.search_range",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_add_dnsmasq_range(
    ctx: Context,
    interface: str,
    start_addr: str,
    end_addr: str,
    prefix_len: str = "",
    ra_mode: str = "",
    lease_time: str = "24h",
    description: str = "",
) -> dict[str, Any]:
    """Create a new dnsmasq DHCP range and apply the configuration.

    Use this to add DHCPv4 or DHCPv6 address ranges with optional Router
    Advertisement (RA) configuration.

    Args:
        interface: Network interface name (e.g. 'lan', 'opt1', 'opt2').
        start_addr: Start of address range. IPv4: '192.168.1.100'.
                    IPv6: uses suffix notation — '::100' (OPNsense auto-prepends
                    the delegated prefix from the interface config).
        end_addr: End of address range. IPv4: '192.168.1.200'. IPv6: '::200'.
        prefix_len: IPv6 prefix length (e.g. '64'). Include this for IPv6 ranges,
                    omit for IPv4 ranges.
        ra_mode: Router Advertisement mode for IPv6. Options:
                 - 'slaac' — clients use SLAAC (stateless autoconfiguration)
                 - 'ra-stateless' — RA + stateless DHCPv6 (DNS via DHCP)
                 - 'ra-only' — RA only, no DHCPv6 address assignment
                 Omit for IPv4 ranges.
        lease_time: Lease duration (e.g. '24h', '1h', '12h'). Default: '24h'.
        description: Optional description for this range.

    NOTE: Only one RA daemon should run per interface. Do not configure both
    dnsmasq RA and radvd on the same interface.

    NOTE: After creation, the service is automatically reconfigured. Changes
    take effect immediately.

    Note: Requires the dnsmasq DNS/DHCP server.
    Returns: dict with 'result', 'uuid' of the new range, and reconfigure status.
    """
    if not interface.strip():
        return {"error": "interface must not be empty"}
    if not start_addr.strip():
        return {"error": "start_addr must not be empty"}
    if not end_addr.strip():
        return {"error": "end_addr must not be empty"}

    api = get_api(ctx)
    api.require_writes()

    range_config: dict[str, str] = {
        "enabled": "1",
        "interface": interface,
        "start_addr": start_addr,
        "end_addr": end_addr,
        "lease_time": lease_time,
    }
    if prefix_len:
        range_config["prefix_len"] = prefix_len
    if ra_mode:
        range_config["ra_mode"] = ra_mode
    if description:
        range_config["description"] = description

    add_result = await api.post("dnsmasq.settings.add_range", {"range": range_config})

    reconfigure_result = await api.post("dnsmasq.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": add_result.get("result", "unknown"),
        "uuid": add_result.get("uuid", ""),
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_update_dnsmasq_range(
    ctx: Context,
    uuid: str,
    interface: str | None = None,
    start_addr: str | None = None,
    end_addr: str | None = None,
    prefix_len: str | None = None,
    ra_mode: str | None = None,
    lease_time: str | None = None,
    description: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Update a dnsmasq DHCP range by UUID and apply the configuration.

    Use this when you need to change the address range, lease time, RA settings,
    or other properties. Only the parameters you provide are changed; all other
    settings are preserved.

    After update, the dnsmasq service is automatically reconfigured. Changes
    take effect immediately.
    Use opn_list_dnsmasq_ranges first to find the UUID.

    Parameters:
    - uuid: range UUID (from opn_list_dnsmasq_ranges)
    - interface: network interface name (e.g. 'lan', 'opt1')
    - start_addr: start of address range
    - end_addr: end of address range
    - prefix_len: IPv6 prefix length (e.g. '64')
    - ra_mode: Router Advertisement mode ('slaac', 'ra-stateless', 'ra-only')
    - lease_time: lease duration (e.g. '24h', '1h')
    - description: human-readable description
    - enabled: enable/disable the range

    Returns: dict with 'result' (str), 'uuid' (str), and 'reconfigure_status'.
    """
    api = get_api(ctx)
    api.require_writes()

    range_config: dict[str, str] = {}
    if interface is not None:
        range_config["interface"] = interface
    if start_addr is not None:
        range_config["start_addr"] = start_addr
    if end_addr is not None:
        range_config["end_addr"] = end_addr
    if prefix_len is not None:
        range_config["prefix_len"] = prefix_len
    if ra_mode is not None:
        range_config["ra_mode"] = ra_mode
    if lease_time is not None:
        range_config["lease_time"] = lease_time
    if description is not None:
        range_config["description"] = description
    if enabled is not None:
        range_config["enabled"] = "1" if enabled else "0"

    result = await api.post("dnsmasq.settings.set_range", {"range": range_config}, path_suffix=uuid)
    reconfigure_result = await api.post("dnsmasq.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": result.get("result", ""),
        "uuid": uuid,
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_delete_dnsmasq_range(
    ctx: Context,
    uuid: str,
) -> dict[str, Any]:
    """Delete a dnsmasq DHCP range by UUID and apply the configuration.

    The deletion is applied immediately (dnsmasq is reconfigured automatically).
    Use opn_list_dnsmasq_ranges first to find the UUID.
    Returns: dict with 'result' (str), 'uuid' (str), and 'reconfigure_status'.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("dnsmasq.settings.del_range", path_suffix=uuid)
    reconfigure_result = await api.post("dnsmasq.service.reconfigure")
    get_config_cache(ctx).invalidate()

    return {
        "result": result.get("result", ""),
        "uuid": uuid,
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
    }


@mcp.tool()
async def opn_reconfigure_dnsmasq(ctx: Context) -> dict[str, Any]:
    """Apply pending dnsmasq DNS/DHCP configuration changes.

    Use this after manually editing dnsmasq settings to apply the changes
    to the running dnsmasq service.

    Note: opn_add_dnsmasq_range auto-reconfigures, so this is only needed
    for manual edits or troubleshooting.

    Note: Requires the dnsmasq DNS/DHCP server.
    Returns: dict with 'status' indicating success or failure.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("dnsmasq.service.reconfigure")
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "dnsmasq"}

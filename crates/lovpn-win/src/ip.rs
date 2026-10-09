//! Addresses, routes, MTU and DNS through the IP Helper API (IPv4 only, as the profile
//! schema M3 slice supports).
use crate::WinError;
use std::net::Ipv4Addr;
use windows_sys::{
    Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
                DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
                DeleteIpForwardEntry2, FreeInterfaceDnsSettings, FreeMibTable, GetBestRoute2,
                GetInterfaceDnsSettings, GetIpForwardTable2, GetIpInterfaceEntry,
                InitializeIpForwardEntry, InitializeIpInterfaceEntry,
                InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
                MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings,
                SetIpInterfaceEntry,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{AF_INET, IpDadStatePreferred, SOCKADDR_INET},
    },
    core::GUID,
};

fn check(step: &'static str, code: u32) -> Result<(), WinError> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(WinError::new(step, code))
    }
}

fn luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

fn v4(addr: Ipv4Addr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is plain data; all-zero is valid.
    let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    s.Ipv4.sin_family = AF_INET;
    s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
    s
}

/// Where traffic to a destination would leave the machine right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Egress {
    pub luid: u64,
    /// `None` for an on-link destination.
    pub next_hop: Option<Ipv4Addr>,
}

pub fn best_egress(destination: Ipv4Addr) -> Result<Egress, WinError> {
    let dest = v4(destination);
    // SAFETY: plain data; all-zero is valid and is overwritten by the call.
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: plain data; overwritten by the call.
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    // SAFETY: all pointers are valid for the call; null interface/source means "any".
    let code = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &dest,
            0,
            &mut route,
            &mut source,
        )
    };
    check("best-route", code)?;
    // SAFETY: the route was requested for IPv4, so the Ipv4 view is the initialized one.
    let hop = Ipv4Addr::from(unsafe { route.NextHop.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
    Ok(Egress {
        // SAFETY: integer view of the LUID union.
        luid: unsafe { route.InterfaceLuid.Value },
        next_hop: (!hop.is_unspecified()).then_some(hop),
    })
}

/// Gateway endpoints follow the same physical default used by observation. An
/// existing /32 host route must not pin repair to the old uplink. On-link endpoints
/// retain their direct route instead of being forced through a default gateway.
pub fn endpoint_egress(
    destination: Ipv4Addr,
    tunnel: Option<u64>,
) -> Result<Option<Egress>, WinError> {
    let best = best_egress(destination)
        .ok()
        .filter(|e| Some(e.luid) != tunnel);
    if let Some(best) = best
        && best.next_hop.is_none()
    {
        return Ok(Some(best));
    }
    Ok(physical_default(tunnel)?.or(best))
}

pub fn add_address(interface: u64, addr: Ipv4Addr, prefix: u8) -> Result<(), WinError> {
    // SAFETY: plain data, initialized by the call below.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: valid out-pointer.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid(interface);
    row.Address = v4(addr);
    row.OnLinkPrefixLength = prefix;
    // A virtual L3 adapter has no link layer to answer duplicate-address probes, so a
    // tentative address never becomes usable. The address is ours by configuration.
    row.DadState = IpDadStatePreferred;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    // SAFETY: valid pointer to an initialized row.
    check("add-address", unsafe { CreateUnicastIpAddressEntry(&row) })
}

/// Set MTU and a low metric so the tunnel wins ties, and stop the stack probing/advertising.
pub fn configure_interface(interface: u64, mtu: u32) -> Result<(), WinError> {
    // SAFETY: plain data, initialized below.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: valid out-pointer.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid(interface);
    // SAFETY: valid pointer to a row with family and LUID set.
    check("get-interface", unsafe { GetIpInterfaceEntry(&mut row) })?;
    row.NlMtu = mtu;
    row.DadTransmits = 0;
    row.UseAutomaticMetric = false;
    row.Metric = 1;
    row.SitePrefixLength = 0; // required by SetIpInterfaceEntry for IPv4
    // SAFETY: valid pointer to the row just read and modified.
    check("set-interface", unsafe { SetIpInterfaceEntry(&mut row) })
}

/// A route this process created and must remove again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub interface: u64,
    pub destination: Ipv4Addr,
    pub prefix: u8,
    pub next_hop: Option<Ipv4Addr>,
}

/// Add a route, replacing an identical stale one (left by a crash or an earlier session)
/// instead of failing with "already exists".
pub fn add_route(route: &Route, metric: u32) -> Result<(), WinError> {
    let row = forward_row(route, metric);
    // A missing route is the normal case, so this result is deliberately ignored.
    let _ = delete_route(route);
    // SAFETY: valid pointer to an initialized row.
    check("add-route", unsafe { CreateIpForwardEntry2(&row) })
}

pub fn delete_route(route: &Route) -> Result<(), WinError> {
    let row = forward_row(route, 0);
    // SAFETY: valid pointer to an initialized row identifying the route.
    check("delete-route", unsafe { DeleteIpForwardEntry2(&row) })
}

fn forward_row(route: &Route, metric: u32) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: plain data, initialized by the call below.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: valid out-pointer.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(route.interface);
    row.DestinationPrefix.Prefix = v4(route.destination);
    row.DestinationPrefix.PrefixLength = route.prefix;
    row.NextHop = v4(route.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED));
    row.Metric = metric;
    row.Protocol = 3; // MIB_IPPROTO_NETMGMT
    row
}

/// Point the tunnel interface's resolvers at the profile's servers.
pub fn set_dns(interface: u64, servers: &[Ipv4Addr]) -> Result<(), WinError> {
    let mut guid = GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };
    let l = luid(interface);
    // SAFETY: valid pointers.
    check("interface-guid", unsafe {
        ConvertInterfaceLuidToGuid(&l, &mut guid)
    })?;
    let list: String = servers
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut wide: Vec<u16> = list.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: plain data; only the fields set below are read given the Flags value.
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = u64::from(DNS_SETTING_NAMESERVER);
    settings.NameServer = wide.as_mut_ptr();
    // SAFETY: `guid` and `settings` are valid; `wide` outlives the call.
    check("set-dns", unsafe {
        SetInterfaceDnsSettings(guid, &settings)
    })
}

/// The tunnel interface's configured DNS servers, as observed (not as requested).
pub fn dns_servers(interface: u64) -> Result<Vec<String>, WinError> {
    let mut guid = GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };
    let l = luid(interface);
    // SAFETY: valid pointers.
    check("interface-guid", unsafe {
        ConvertInterfaceLuidToGuid(&l, &mut guid)
    })?;
    // SAFETY: plain data; the call fills the fields selected by Flags.
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = u64::from(DNS_SETTING_NAMESERVER);
    // SAFETY: valid GUID and settings; freed below.
    check("get-dns", unsafe {
        GetInterfaceDnsSettings(guid, &mut settings)
    })?;
    let mut text = String::new();
    if !settings.NameServer.is_null() {
        let mut len = 0;
        // SAFETY: the API returns a NUL-terminated UTF-16 string.
        while unsafe { *settings.NameServer.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` elements were just read.
        text = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(settings.NameServer, len)
        });
    }
    // SAFETY: the settings were filled by GetInterfaceDnsSettings.
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    Ok(text
        .split([',', ' ', ';'])
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

/// The best IPv4 default route that does not use `exclude_luid` (the tunnel): the physical
/// uplink, by lowest route metric plus interface metric.
pub fn physical_default(exclude_luid: Option<u64>) -> Result<Option<Egress>, WinError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: valid out-pointer; the table is freed below.
    check("route-table", unsafe {
        GetIpForwardTable2(AF_INET, &mut table)
    })?;
    // SAFETY: the call succeeded, so `table` points at NumEntries valid rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut best: Option<(u32, Egress)> = None;
    for row in rows {
        // SAFETY: IPv4 table, so the Ipv4 view of the address unions is the valid one.
        let (dest, prefix, hop, l) = unsafe {
            (
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr,
                row.DestinationPrefix.PrefixLength,
                row.NextHop.Ipv4.sin_addr.S_un.S_addr,
                row.InterfaceLuid.Value,
            )
        };
        if dest != 0 || prefix != 0 || Some(l) == exclude_luid {
            continue;
        }
        let mut interface: MIB_IPINTERFACE_ROW = {
            // SAFETY: plain data, initialized below.
            let mut r: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
            // SAFETY: valid out-pointer.
            unsafe { InitializeIpInterfaceEntry(&mut r) };
            r.Family = AF_INET;
            r.InterfaceLuid = luid(l);
            r
        };
        // SAFETY: valid row with family and LUID set.
        if unsafe { GetIpInterfaceEntry(&mut interface) } != NO_ERROR || !interface.Connected {
            continue;
        }
        let metric = row.Metric.saturating_add(interface.Metric);
        let hop = Ipv4Addr::from(hop.to_ne_bytes());
        let egress = Egress {
            luid: l,
            next_hop: (!hop.is_unspecified()).then_some(hop),
        };
        if best.as_ref().is_none_or(|(m, _)| metric < *m) {
            best = Some((metric, egress));
        }
    }
    // SAFETY: allocated by GetIpForwardTable2, freed exactly once.
    unsafe { FreeMibTable(table.cast()) };
    Ok(best.map(|(_, e)| e))
}

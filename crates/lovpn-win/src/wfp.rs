//! Windows Filtering Platform: installs, verifies and removes the persistent LoVPN policy
//! compiled by [`crate::policy`].
//!
//! Filters are persistent (they survive a service crash and reboot, so a crash cannot open
//! the network) and owned by one LoVPN provider and sublayer. Replacement is a single WFP
//! transaction: there is never a moment with the old policy removed and the new one absent.
use crate::{
    WinError,
    policy::{Action, BOOT_LAYERS, Condition, FilterSpec, LAYERS, Layer, compile_boot},
};
use std::{ffi::c_void, os::windows::ffi::OsStrExt};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_SUCCESS, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::GUID,
};

/// {4C6F5650-4E00-4000-8C1F-4C6F56504E10}
#[cfg(not(test))]
const PROVIDER: GUID = GUID {
    data1: 0x4c6f_5650,
    data2: 0x4e00,
    data3: 0x4000,
    data4: [0x8c, 0x1f, 0x4c, 0x6f, 0x56, 0x50, 0x4e, 0x10],
};
/// {4C6F5650-4E00-4000-8C1F-4C6F56504E11}
#[cfg(not(test))]
const SUBLAYER: GUID = GUID {
    data1: 0x4c6f_5650,
    data2: 0x4e00,
    data3: 0x4000,
    data4: [0x8c, 0x1f, 0x4c, 0x6f, 0x56, 0x50, 0x4e, 0x11],
};
// Test builds exclusively use a different namespace, including all cleanup paths.
#[cfg(test)]
const PROVIDER: GUID = GUID {
    data1: 0x4c6f_5650,
    data2: 0x4e00,
    data3: 0x4000,
    data4: [0x8c, 0x1f, 0x4c, 0x6f, 0x56, 0x50, 0x4e, 0xe0],
};
#[cfg(test)]
const SUBLAYER: GUID = GUID {
    data1: 0x4c6f_5650,
    data2: 0x4e00,
    data3: 0x4000,
    data4: [0x8c, 0x1f, 0x4c, 0x6f, 0x56, 0x50, 0x4e, 0xe1],
};
const SERVICE_NAME: &str = "LoVPNClient";
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const NAME_PREFIX: &str = "LoVPN g";

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn check(step: &'static str, code: u32) -> Result<(), WinError> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(WinError::new(step, code))
    }
}

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        Layer::BootInboundV4 => FWPM_LAYER_INBOUND_IPPACKET_V4,
        Layer::BootInboundV6 => FWPM_LAYER_INBOUND_IPPACKET_V6,
        Layer::BootOutboundV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        Layer::BootOutboundV6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    }
}

fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

// SAFETY: callers supply an engine-owned filter whose pointed-to values remain alive.
unsafe fn filter_mismatch(
    filter: &FWPM_FILTER0,
    spec: &FilterSpec,
) -> Result<Option<&'static str>, WinError> {
    let flags = if BOOT_LAYERS.contains(&spec.layer) {
        FWPM_FILTER_FLAG_BOOTTIME
    } else {
        FWPM_FILTER_FLAG_PERSISTENT
    };
    if filter.flags & FWPM_FILTER_FLAG_DISABLED != 0 {
        return Ok(Some("wfp-mismatch-disabled"));
    }
    // INDEXED only changes lookup performance, not action/rights/persistence semantics.
    if filter.flags & !FWPM_FILTER_FLAG_INDEXED != flags {
        return Ok(Some("wfp-mismatch-flags"));
    }
    if !same_guid(filter.layerKey, layer_key(spec.layer)) {
        return Ok(Some("wfp-mismatch-layer"));
    }
    if !same_guid(filter.subLayerKey, SUBLAYER) {
        return Ok(Some("wfp-mismatch-sublayer"));
    }
    if filter.providerKey.is_null() {
        return Ok(Some("wfp-mismatch-provider-null"));
    }
    // SAFETY: non-null key belongs to the engine allocation.
    if !same_guid(unsafe { *filter.providerKey }, PROVIDER) {
        return Ok(Some("wfp-mismatch-provider"));
    }
    if filter.action.r#type
        != match spec.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        }
    {
        return Ok(Some("wfp-mismatch-action"));
    }
    if filter.effectiveWeight.r#type != FWP_UINT64 {
        return Ok(Some("wfp-mismatch-effective-weight-type"));
    }
    // SAFETY: union type above selects the pointer to the engine-owned u64.
    let effective = unsafe { filter.effectiveWeight.Anonymous.uint64 };
    if effective.is_null() {
        return Ok(Some("wfp-mismatch-effective-weight-null"));
    }
    // Microsoft Filter Weight Assignment: UINT8 0..15 selects the high four bits;
    // BFE owns the lower 60 bits. Never compare the effective weight to the range index.
    // SAFETY: non-null engine-owned u64 checked above.
    let effective = unsafe { *effective };
    if spec.weight > 15 || effective >> 60 != u64::from(spec.weight) {
        return Ok(Some("wfp-mismatch-effective-weight-range"));
    }
    // Accept the original selector or its semantically equivalent resolved UINT64,
    // requiring the latter to equal effectiveWeight exactly (not just its range).
    // SAFETY: each union access is guarded by the weight type discriminant.
    let weight_matches = unsafe {
        match filter.weight.r#type {
            FWP_UINT8 => filter.weight.Anonymous.uint8 == spec.weight,
            FWP_UINT64 => {
                !filter.weight.Anonymous.uint64.is_null()
                    && *filter.weight.Anonymous.uint64 == effective
            }
            _ => return Ok(Some("wfp-mismatch-weight-type")),
        }
    };
    if !weight_matches {
        return Ok(Some("wfp-mismatch-weight-value"));
    }
    if filter.numFilterConditions as usize != spec.conditions.len() {
        return Ok(Some("wfp-mismatch-condition-count"));
    }
    if filter.numFilterConditions == 0 {
        return Ok(None);
    }
    if filter.filterCondition.is_null() {
        return Ok(Some("wfp-mismatch-condition-null"));
    }
    // SAFETY: WFP returned numFilterConditions initialized condition entries.
    let observed = unsafe {
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
    };
    let mut used = vec![false; observed.len()];
    for expected in &spec.conditions {
        let mut found = false;
        for (i, condition) in observed.iter().enumerate() {
            // SAFETY: condition values are alive for the same engine allocation.
            if !used[i] && unsafe { matches_condition(condition, expected) }? {
                used[i] = true;
                found = true;
                break;
            }
        }
        if !found {
            return Ok(Some(match expected {
                Condition::Loopback => "wfp-mismatch-condition-loopback",
                Condition::Interface(_) => "wfp-mismatch-condition-interface",
                Condition::RemoteAddress(_) => "wfp-mismatch-condition-address",
                Condition::RemotePort(_) => "wfp-mismatch-condition-remote-port",
                Condition::LocalPort(_) => "wfp-mismatch-condition-local-port",
                Condition::Protocol(_) => "wfp-mismatch-condition-protocol",
                Condition::Application(_) => "wfp-mismatch-condition-app-id",
            }));
        }
    }
    Ok(None)
}

// SAFETY: c must be an engine-owned condition with valid pointers selected by its type.
unsafe fn matches_condition(
    c: &FWPM_FILTER_CONDITION0,
    expected: &Condition,
) -> Result<bool, WinError> {
    let value = &c.conditionValue;
    let (key, kind, match_type) = match expected {
        Condition::Loopback => (FWPM_CONDITION_FLAGS, FWP_UINT32, FWP_MATCH_FLAGS_ALL_SET),
        Condition::Interface(_) => (
            FWPM_CONDITION_IP_LOCAL_INTERFACE,
            FWP_UINT64,
            FWP_MATCH_EQUAL,
        ),
        Condition::RemoteAddress(_) => (
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_UINT32,
            FWP_MATCH_EQUAL,
        ),
        Condition::RemotePort(_) => (FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16, FWP_MATCH_EQUAL),
        Condition::LocalPort(_) => (FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16, FWP_MATCH_EQUAL),
        Condition::Protocol(_) => (FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, FWP_MATCH_EQUAL),
        Condition::Application(_) => (
            FWPM_CONDITION_ALE_APP_ID,
            FWP_BYTE_BLOB_TYPE,
            FWP_MATCH_EQUAL,
        ),
    };
    if !same_guid(c.fieldKey, key) || value.r#type != kind || c.matchType != match_type {
        return Ok(false);
    }
    // SAFETY: the type discriminant was checked above before any union/pointer access.
    Ok(unsafe {
        match expected {
            Condition::Loopback => value.Anonymous.uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK,
            Condition::Interface(luid) => {
                !value.Anonymous.uint64.is_null() && *value.Anonymous.uint64 == *luid
            }
            Condition::RemoteAddress(ip) => value.Anonymous.uint32 == u32::from(*ip),
            Condition::RemotePort(port) | Condition::LocalPort(port) => {
                value.Anonymous.uint16 == *port
            }
            Condition::Protocol(protocol) => value.Anonymous.uint8 == *protocol,
            Condition::Application(path) => {
                let have = value.Anonymous.byteBlob;
                if have.is_null() {
                    return Ok(false);
                }
                let mut expected_blob = std::ptr::null_mut();
                let path = wide(path);
                check(
                    "wfp-verify-app-id",
                    FwpmGetAppIdFromFileName0(path.as_ptr(), &mut expected_blob),
                )?;
                let equal = !expected_blob.is_null()
                    && (*have).size == (*expected_blob).size
                    && (*have).size > 0
                    && !(*have).data.is_null()
                    && !(*expected_blob).data.is_null()
                    && std::slice::from_raw_parts((*have).data, (*have).size as usize)
                        == std::slice::from_raw_parts(
                            (*expected_blob).data,
                            (*expected_blob).size as usize,
                        );
                FwpmFreeMemory0(std::ptr::addr_of_mut!(expected_blob).cast::<*mut c_void>());
                equal
            }
        }
    })
}

/// An open handle to the filtering engine.
pub struct Engine {
    handle: HANDLE,
}

// SAFETY: WFP engine handles may be used from any thread; callers serialize use behind
// the service's engine mutex, and transactions are begun and finished within one call.
unsafe impl Send for Engine {}

impl Engine {
    /// Verify a single consistent WFP snapshot against every runtime and boot spec.
    /// Unknown, duplicate, stale, disabled or semantically altered provider filters fail.
    pub fn verifies(&self, specs: &[FilterSpec]) -> Result<bool, WinError> {
        self.verification_diagnostic(specs)
            .map(|mismatch| mismatch.is_none())
    }

    /// Static field category only: never includes addresses, paths, blob bytes or names.
    pub fn verification_diagnostic(
        &self,
        specs: &[FilterSpec],
    ) -> Result<Option<&'static str>, WinError> {
        // SAFETY: valid engine handle; this transaction never mutates WFP state.
        check("wfp-verify-begin", unsafe {
            FwpmTransactionBegin0(self.handle, FWPM_TXN_READ_ONLY)
        })?;
        let expected: Vec<_> = specs.iter().cloned().chain(compile_boot(specs)).collect();
        let result: Result<Option<&'static str>, WinError> = (|| {
            for layer in LAYERS.into_iter().chain(BOOT_LAYERS) {
                let have = self.enumerate_inner(layer, Some(&expected))?;
                if have.len() != expected.iter().filter(|s| s.layer == layer).count() {
                    return Ok(Some("wfp-mismatch-filter-count"));
                }
                let mut names: Vec<_> = have.iter().map(|f| &f.1).collect();
                names.sort();
                if names.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Ok(Some("wfp-mismatch-duplicate-name"));
                }
            }
            Ok(None)
        })();
        // SAFETY: end the read-only transaction even on an observation error.
        let abort = check("wfp-verify-end", unsafe {
            FwpmTransactionAbort0(self.handle)
        });
        abort?;
        match result {
            Err(e) if e.step.starts_with("wfp-mismatch-") => Ok(Some(e.step)),
            other => other,
        }
    }
    pub fn open() -> Result<Self, WinError> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: null server/identity/session select the local engine with defaults;
        // `handle` is a valid out-pointer.
        let code = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut handle,
            )
        };
        check("wfp-open", code)?;
        Ok(Self { handle })
    }

    /// Atomically replace LoVPN's whole policy with `specs`.
    pub fn replace(&self, specs: &[FilterSpec]) -> Result<(), WinError> {
        // SAFETY: valid engine handle.
        check("wfp-begin", unsafe {
            FwpmTransactionBegin0(self.handle, 0)
        })?;
        let result = self
            .ensure_provider_and_sublayer()
            .and_then(|()| self.delete_all_inner())
            .and_then(|()| {
                specs
                    .iter()
                    .chain(compile_boot(specs).iter())
                    .try_for_each(|s| self.add(s))
            });
        match result {
            Ok(()) => {
                // SAFETY: a transaction is open on this handle.
                self.commit()
            }
            Err(error) => {
                // SAFETY: a transaction is open; aborting restores the previous policy.
                unsafe { FwpmTransactionAbort0(self.handle) };
                Err(error)
            }
        }
    }

    /// Remove every LoVPN filter (the explicit kill-switch release).
    pub fn remove_all(&self) -> Result<(), WinError> {
        // SAFETY: valid engine handle.
        check("wfp-begin", unsafe {
            FwpmTransactionBegin0(self.handle, 0)
        })?;
        match self.delete_all_inner() {
            Ok(()) => {
                // SAFETY: a transaction is open on this handle.
                self.commit()
            }
            Err(error) => {
                // SAFETY: a transaction is open on this handle.
                unsafe { FwpmTransactionAbort0(self.handle) };
                Err(error)
            }
        }
    }

    fn commit(&self) -> Result<(), WinError> {
        // SAFETY: a transaction was begun by the caller on this handle.
        let result = check("wfp-commit", unsafe { FwpmTransactionCommit0(self.handle) });
        if result.is_err() {
            // SAFETY: best-effort abort if commit failed and left a transaction open.
            // Never retry a possibly committed replacement or remove protection here.
            unsafe { FwpmTransactionAbort0(self.handle) };
        }
        result
    }

    /// Names of the LoVPN filters currently installed (observed, not remembered).
    pub fn installed(&self) -> Result<Vec<String>, WinError> {
        let mut names = Vec::new();
        let mut runtime = Vec::new();
        for layer in LAYERS {
            for filter in self.enumerate(layer)? {
                if filter.2 & FWPM_FILTER_FLAG_DISABLED != 0 {
                    return Err(WinError::new("wfp-filter-disabled", 13));
                }
                if filter.2 & FWPM_FILTER_FLAG_PERSISTENT == 0 {
                    return Err(WinError::new("wfp-filter-not-persistent", 13));
                }
                names.push(filter.1);
            }
        }
        // Observe boot protection separately: engine callers compare ALE names only.
        // Missing boot filters must nevertheless make policy verification fail closed.
        for name in &names {
            if name.contains(" block-all c4") {
                runtime.push(FilterSpec {
                    name: name.clone(),
                    layer: Layer::ConnectV4,
                    action: Action::Block,
                    weight: 1,
                    conditions: Vec::new(),
                });
            }
        }
        let mut expected_boot: Vec<_> =
            compile_boot(&runtime).into_iter().map(|f| f.name).collect();
        let mut actual_boot = Vec::new();
        for layer in BOOT_LAYERS {
            for (_, name, flags) in self.enumerate(layer)? {
                if flags & FWPM_FILTER_FLAG_BOOTTIME == 0 || flags & FWPM_FILTER_FLAG_DISABLED != 0
                {
                    return Err(WinError::new("wfp-boot-flags", 13));
                }
                actual_boot.push(name);
            }
        }
        expected_boot.sort();
        actual_boot.sort();
        if actual_boot != expected_boot {
            return Err(WinError::new("wfp-boot-policy-mismatch", 13));
        }
        names.sort();
        Ok(names)
    }

    fn ensure_provider_and_sublayer(&self) -> Result<(), WinError> {
        let mut existing: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
        // SAFETY: valid handle and provider key; output freed before metadata migration.
        let code = unsafe { FwpmProviderGetByKey0(self.handle, &PROVIDER, &mut existing) };
        if code == ERROR_SUCCESS {
            // SAFETY: successful WFP query returned a valid provider allocation.
            let migrate = unsafe {
                (*existing).flags != FWPM_PROVIDER_FLAG_PERSISTENT
                    || read_wide((*existing).serviceName) != SERVICE_NAME
            };
            // SAFETY: allocated by FwpmProviderGetByKey0.
            unsafe { FwpmFreeMemory0(std::ptr::addr_of_mut!(existing).cast::<*mut c_void>()) };
            if migrate {
                // WFP has no provider update API. Migrate dependencies inside the same
                // replacement transaction, so any failure restores the entire old policy.
                // Unknown provider dependencies prevent deletion and abort conservatively.
                self.delete_all_inner()?;
                // SAFETY: called only within the open replacement transaction.
                let code = unsafe { FwpmSubLayerDeleteByKey0(self.handle, &SUBLAYER) };
                if code != windows_sys::Win32::Foundation::FWP_E_SUBLAYER_NOT_FOUND as u32 {
                    check("wfp-provider-migrate-sublayer", code)?;
                }
                // SAFETY: dependencies removed above; rollback restores them on failure.
                check("wfp-provider-migrate", unsafe {
                    FwpmProviderDeleteByKey0(self.handle, &PROVIDER)
                })?;
            }
        } else if code != windows_sys::Win32::Foundation::FWP_E_PROVIDER_NOT_FOUND as u32 {
            check("wfp-provider-inspect", code)?;
        }
        let mut name = wide("LoVPN");
        let mut service_name = wide(SERVICE_NAME);
        // SAFETY: plain data, filled in below.
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.providerKey = PROVIDER;
        provider.displayData.name = name.as_mut_ptr();
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        // Without an auto-start service association, BFE can mark this provider's
        // persistent filters DISABLED on restart. Never treat DISABLED as cosmetic.
        provider.serviceName = service_name.as_mut_ptr();
        // SAFETY: valid handle and pointer; `name` outlives the call.
        let code = unsafe { FwpmProviderAdd0(self.handle, &provider, std::ptr::null_mut()) };
        if code != FWP_E_ALREADY_EXISTS {
            check("wfp-provider", code)?;
        }
        // SAFETY: plain data, filled in below.
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = SUBLAYER;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        let mut provider_key = PROVIDER;
        sublayer.providerKey = &mut provider_key;
        sublayer.weight = 0xFFFF; // evaluated before every other sublayer
        // SAFETY: valid handle and pointers; both outlive the call.
        let code = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, std::ptr::null_mut()) };
        if code != FWP_E_ALREADY_EXISTS {
            check("wfp-sublayer", code)?;
        }
        Ok(())
    }

    /// (filter id, display name) of this provider's filters on one layer.
    fn enumerate(&self, layer: Layer) -> Result<Vec<(u64, String, u32)>, WinError> {
        self.enumerate_inner(layer, None)
    }

    fn enumerate_inner(
        &self,
        layer: Layer,
        expected: Option<&[FilterSpec]>,
    ) -> Result<Vec<(u64, String, u32)>, WinError> {
        let mut provider_key = PROVIDER;
        // SAFETY: plain data, filled in below.
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = &mut provider_key;
        template.layerKey = layer_key(layer);
        template.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        template.flags =
            FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
        template.actionMask = 0xFFFF_FFFF;
        let mut enum_handle: HANDLE = std::ptr::null_mut();
        // SAFETY: valid handle; template and its provider key outlive the call.
        check("wfp-enum-create", unsafe {
            FwpmFilterCreateEnumHandle0(self.handle, &template, &mut enum_handle)
        })?;
        let mut found = Vec::new();
        let mut outcome = Ok(());
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count: u32 = 0;
            // SAFETY: valid handles and out-pointers; the entries array is freed below.
            let code =
                unsafe { FwpmFilterEnum0(self.handle, enum_handle, 100, &mut entries, &mut count) };
            if code != ERROR_SUCCESS {
                outcome = Err(WinError::new("wfp-enum", code));
                break;
            }
            for i in 0..count as usize {
                // SAFETY: the engine returned `count` valid filter pointers.
                let filter = unsafe { &**entries.add(i) };
                #[cfg(test)]
                if expected.is_some() {
                    let weight_kind = match filter.weight.r#type {
                        FWP_UINT8 => "range-u8",
                        FWP_UINT64 => "resolved-u64",
                        FWP_EMPTY => "automatic-empty",
                        _ => "other",
                    };
                    let effective_kind = match filter.effectiveWeight.r#type {
                        FWP_UINT64 => "u64",
                        FWP_EMPTY => "empty",
                        _ => "other",
                    };
                    let flag_kind = if filter.flags & FWPM_FILTER_FLAG_DISABLED != 0 {
                        "disabled"
                    } else if filter.flags & FWPM_FILTER_FLAG_INDEXED != 0 {
                        "enabled-indexed"
                    } else {
                        "enabled-unindexed"
                    };
                    eprintln!(
                        "WFP_STATIC_SHAPE layer={} weight={weight_kind} effective={effective_kind} flags={flag_kind}",
                        layer.tag()
                    );
                }
                // SAFETY: display name is a NUL-terminated UTF-16 string owned by the engine.
                let name = unsafe { read_wide(filter.displayData.name) };
                if let Some(specs) = expected {
                    let matched = match specs.iter().find(|s| s.layer == layer && s.name == name) {
                        // SAFETY: the enumeration allocation is not freed until below.
                        Some(spec) => unsafe { filter_mismatch(filter, spec) },
                        None => Ok(Some("wfp-mismatch-unexpected-filter")),
                    };
                    match matched {
                        Ok(None) => {}
                        Ok(Some(reason)) if outcome.is_ok() => {
                            #[cfg(test)]
                            eprintln!("WFP_STATIC_MISMATCH layer={} field={reason}", layer.tag());
                            outcome = Err(WinError::new(reason, 13));
                        }
                        Err(e) if outcome.is_ok() => outcome = Err(e),
                        _ => {}
                    }
                }
                // Boot observation must validate a real unconditional block, not just
                // a display name. Mark invalid observations as disabled locally; deletion
                // still enumerates their IDs so explicit recovery can remove them.
                let mut flags = filter.flags;
                if BOOT_LAYERS.contains(&layer)
                    && (filter.action.r#type != FWP_ACTION_BLOCK
                        || filter.numFilterConditions != 0
                        || filter.subLayerKey.data1 != SUBLAYER.data1
                        || filter.subLayerKey.data2 != SUBLAYER.data2
                        || filter.subLayerKey.data3 != SUBLAYER.data3
                        || filter.subLayerKey.data4 != SUBLAYER.data4)
                {
                    flags |= FWPM_FILTER_FLAG_DISABLED;
                }
                found.push((filter.filterId, name, flags));
            }
            // SAFETY: `entries` was allocated by FwpmFilterEnum0.
            unsafe { FwpmFreeMemory0(std::ptr::addr_of_mut!(entries).cast::<*mut c_void>()) };
            if count < 100 {
                break;
            }
        }
        // SAFETY: the enum handle was created above and is destroyed once.
        unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
        outcome?;
        if expected.is_none() {
            found.retain(|(_, name, _)| name.starts_with(NAME_PREFIX));
        }
        Ok(found)
    }

    fn delete_all_inner(&self) -> Result<(), WinError> {
        for layer in LAYERS.into_iter().chain(BOOT_LAYERS) {
            for (id, _, _) in self.enumerate(layer)? {
                // SAFETY: valid handle; the id was just enumerated in this transaction.
                check("wfp-delete", unsafe {
                    FwpmFilterDeleteById0(self.handle, id)
                })?;
            }
        }
        Ok(())
    }

    fn add(&self, spec: &FilterSpec) -> Result<(), WinError> {
        // Storage for condition values: pointers into these must stay valid for the call.
        let mut u64s: Vec<Box<u64>> = Vec::new();
        let mut blobs: Vec<*mut FWP_BYTE_BLOB> = Vec::new();
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        let mut build: Result<(), WinError> = Ok(());
        for condition in &spec.conditions {
            // SAFETY: plain data, fully set below.
            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            c.matchType = FWP_MATCH_EQUAL;
            match condition {
                Condition::Loopback => {
                    c.fieldKey = FWPM_CONDITION_FLAGS;
                    c.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    c.conditionValue.r#type = FWP_UINT32;
                    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                }
                Condition::Interface(luid) => {
                    c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                    let mut boxed = Box::new(*luid);
                    c.conditionValue.r#type = FWP_UINT64;
                    c.conditionValue.Anonymous.uint64 = &mut *boxed;
                    u64s.push(boxed);
                }
                Condition::RemoteAddress(ip) => {
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    c.conditionValue.r#type = FWP_UINT32;
                    c.conditionValue.Anonymous.uint32 = u32::from(*ip);
                }
                Condition::RemotePort(port) => {
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    c.conditionValue.r#type = FWP_UINT16;
                    c.conditionValue.Anonymous.uint16 = *port;
                }
                Condition::LocalPort(port) => {
                    c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    c.conditionValue.r#type = FWP_UINT16;
                    c.conditionValue.Anonymous.uint16 = *port;
                }
                Condition::Protocol(p) => {
                    c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    c.conditionValue.r#type = FWP_UINT8;
                    c.conditionValue.Anonymous.uint8 = *p;
                }
                Condition::Application(path) => {
                    let w = wide(path);
                    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                    // SAFETY: NUL-terminated path; the blob is freed below.
                    let code = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
                    if let Err(e) = check("wfp-app-id", code) {
                        build = Err(e);
                        break;
                    }
                    blobs.push(blob);
                    c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    c.conditionValue.Anonymous.byteBlob = blob;
                }
            }
            conditions.push(c);
        }
        let result = build.and_then(|()| {
            let mut name = wide(&spec.name);
            let mut provider_key = PROVIDER;
            // SAFETY: plain data, filled in below.
            let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            filter.displayData.name = name.as_mut_ptr();
            filter.flags = if BOOT_LAYERS.contains(&spec.layer) {
                FWPM_FILTER_FLAG_BOOTTIME
            } else {
                FWPM_FILTER_FLAG_PERSISTENT
            };
            filter.providerKey = &mut provider_key;
            filter.layerKey = layer_key(spec.layer);
            filter.subLayerKey = SUBLAYER;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = spec.weight;
            filter.numFilterConditions = u32::try_from(conditions.len()).unwrap_or(0);
            filter.filterCondition = if conditions.is_empty() {
                std::ptr::null_mut()
            } else {
                conditions.as_mut_ptr()
            };
            filter.action.r#type = match spec.action {
                Action::Permit => FWP_ACTION_PERMIT,
                Action::Block => FWP_ACTION_BLOCK,
            };
            let mut id: u64 = 0;
            // SAFETY: the filter, its conditions, name, provider key and condition value
            // storage all outlive the call; the security descriptor is optional (null).
            check("wfp-add", unsafe {
                FwpmFilterAdd0(self.handle, &filter, std::ptr::null_mut(), &mut id)
            })
        });
        for mut blob in blobs {
            // SAFETY: allocated by FwpmGetAppIdFromFileName0, freed exactly once.
            unsafe { FwpmFreeMemory0(std::ptr::addr_of_mut!(blob).cast::<*mut c_void>()) };
        }
        result
    }
}

/// # Safety
/// `p` must be null or point at a NUL-terminated UTF-16 string.
unsafe fn read_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: guaranteed NUL-terminated by the caller.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` elements were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
        unsafe { FwpmEngineClose0(self.handle) };
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::policy::{self, PolicyInput};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn verify_static(
        engine: &Engine,
        specs: &[FilterSpec],
        stage: &'static str,
    ) -> Result<bool, WinError> {
        let result = engine.verification_diagnostic(specs);
        eprintln!("WFP_STATIC_VERIFICATION stage={stage} outcome={result:?}");
        result.map(|reason| reason.is_none())
    }

    #[test]
    fn normalized_weight_and_flag_semantics() -> Result<(), WinError> {
        let spec = FilterSpec {
            name: "unused".into(),
            layer: Layer::ConnectV4,
            action: Action::Block,
            weight: 12,
            conditions: Vec::new(),
        };
        let mut provider = PROVIDER;
        let mut effective = (12u64 << 60) | 123;
        let mut resolved = effective;
        // SAFETY: plain FFI data initialized below, with local pointers alive throughout.
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        filter.providerKey = &mut provider;
        filter.layerKey = layer_key(spec.layer);
        filter.subLayerKey = SUBLAYER;
        filter.action.r#type = FWP_ACTION_BLOCK;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = spec.weight;
        filter.effectiveWeight.r#type = FWP_UINT64;
        filter.effectiveWeight.Anonymous.uint64 = &mut effective;
        // SAFETY: all union types and pointed-to local storage were initialized above.
        assert_eq!(unsafe { filter_mismatch(&filter, &spec) }?, None);
        filter.flags |= FWPM_FILTER_FLAG_INDEXED;
        // SAFETY: only the flags changed; storage remains live.
        assert_eq!(unsafe { filter_mismatch(&filter, &spec) }?, None);
        filter.weight.r#type = FWP_UINT64;
        filter.weight.Anonymous.uint64 = &mut resolved;
        // SAFETY: weight now selects initialized local u64 storage.
        assert_eq!(unsafe { filter_mismatch(&filter, &spec) }?, None);
        filter.flags |= FWPM_FILTER_FLAG_DISABLED;
        // SAFETY: all pointed-to storage remains live.
        assert_eq!(
            // SAFETY: all pointed-to storage remains live.
            unsafe { filter_mismatch(&filter, &spec) }?,
            Some("wfp-mismatch-disabled")
        );
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        // SAFETY: all pointed-to storage remains live.
        assert_eq!(
            // SAFETY: all pointed-to storage remains live.
            unsafe { filter_mismatch(&filter, &spec) }?,
            Some("wfp-mismatch-flags")
        );
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        resolved += 1;
        // SAFETY: weight/effective-weight point at distinct live u64 values.
        assert_eq!(
            // SAFETY: both weight values are backed by live local storage.
            unsafe { filter_mismatch(&filter, &spec) }?,
            Some("wfp-mismatch-weight-value")
        );
        effective = (11u64 << 60) | 123;
        // SAFETY: the effective value changed; its pointer remains valid.
        assert_eq!(
            // SAFETY: effective weight pointer remains valid after the local mutation.
            unsafe { filter_mismatch(&filter, &spec) }?,
            Some("wfp-mismatch-effective-weight-range")
        );
        // Ensure the local mutations above are retained and observable through FFI pointers.
        assert_ne!(resolved, effective);
        Ok(())
    }

    struct Cleanup(Engine);
    impl Cleanup {
        fn release(&self) -> Result<(), WinError> {
            self.0.remove_all()?;
            // SAFETY: preflight proved these objects absent; this test created them.
            check("test-delete-sublayer", unsafe {
                FwpmSubLayerDeleteByKey0(self.0.handle, &SUBLAYER)
            })?;
            // SAFETY: test-owned provider has no remaining sublayer or filters.
            check("test-delete-provider", unsafe {
                FwpmProviderDeleteByKey0(self.0.handle, &PROVIDER)
            })
        }
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            // Always attempt filter cleanup, including assertion failures/unwinding.
            // Successful explicit cleanup leaves no metadata; repeated deletes may fail.
            if let Err(error) = self.0.remove_all() {
                eprintln!("DISPOSABLE VM WFP CLEANUP FAILED: {error}");
                return;
            }
            // SAFETY: objects were absent before the test, and filters were removed above.
            unsafe {
                FwpmSubLayerDeleteByKey0(self.0.handle, &SUBLAYER);
                FwpmProviderDeleteByKey0(self.0.handle, &PROVIDER);
            }
        }
    }

    /// DISRUPTIVE: blocks all external IP traffic and persists boot protection temporarily.
    /// Run elevated only on a disposable Windows VM. Test builds use isolated GUIDs,
    /// so production LoVPN metadata is never modified. Strict preflight refuses even
    /// empty pre-existing TEST provider/sublayer metadata. Does not test a reboot handoff.
    #[test]
    #[ignore = "DISRUPTIVE: elevated disposable Windows VM only; temporarily blocks networking"]
    fn elevated_disposable_vm_runtime_and_boot_roundtrip() -> Result<(), Box<dyn std::error::Error>>
    {
        use windows_sys::Win32::Foundation::{FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND};
        let engine = Engine::open()?;
        let mut provider = std::ptr::null_mut();
        // SAFETY: valid engine and output pointer; allocation freed before asserting.
        let code = unsafe { FwpmProviderGetByKey0(engine.handle, &PROVIDER, &mut provider) };
        if !provider.is_null() {
            // SAFETY: allocated by WFP above.
            unsafe { FwpmFreeMemory0(std::ptr::addr_of_mut!(provider).cast::<*mut c_void>()) };
        }
        if code != FWP_E_PROVIDER_NOT_FOUND as u32 {
            return Err(std::io::Error::other(
                "refusing existing isolated TEST provider or failed preflight",
            )
            .into());
        }
        let mut sublayer = std::ptr::null_mut();
        // SAFETY: valid handle and output pointer.
        let code = unsafe { FwpmSubLayerGetByKey0(engine.handle, &SUBLAYER, &mut sublayer) };
        if !sublayer.is_null() {
            // SAFETY: allocated by WFP above.
            unsafe { FwpmFreeMemory0(std::ptr::addr_of_mut!(sublayer).cast::<*mut c_void>()) };
        }
        if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return Err(std::io::Error::other(
                "refusing existing isolated TEST sublayer or failed preflight",
            )
            .into());
        }
        assert!(verify_static(&engine, &[], "preflight-empty")?);
        let cleanup = Cleanup(engine);
        let specs = policy::compile(&PolicyInput {
            generation: 1,
            tunnel_interface: None,
            endpoint: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51820),
            service_path: std::env::current_exe()?.to_string_lossy().into_owned(),
            kill_switch: true,
            dns_guard: true,
            block_ipv6: true,
        });
        cleanup.0.replace(&specs)?;
        assert!(verify_static(&cleanup.0, &specs, "runtime-boot-installed")?);
        let mut invalid = specs.clone();
        if let Some(last) = invalid.last_mut() {
            last.weight = 255;
        }
        assert!(
            cleanup.0.replace(&invalid).is_err(),
            "WFP must reject out-of-range weight"
        );
        assert!(
            verify_static(&cleanup.0, &specs, "rollback-preserved")?,
            "failed transaction must preserve runtime AND boot filters"
        );
        let mut altered = specs.clone();
        if let Some(first) = altered.first_mut() {
            first.action = Action::Block;
        }
        cleanup.0.replace(&altered)?;
        assert!(
            !verify_static(&cleanup.0, &specs, "action-tamper-detected")?,
            "unchanged names must not conceal altered actions"
        );
        assert!(verify_static(&cleanup.0, &altered, "altered-specs-match")?);
        cleanup.0.replace(&specs)?;
        cleanup.0.remove_all()?;
        assert!(
            verify_static(&cleanup.0, &[], "runtime-boot-removed")?,
            "release must remove runtime AND boot filters"
        );
        cleanup.release()?;
        Ok(())
    }
}

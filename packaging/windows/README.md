# Windows MSI: NRPT record-v2 compatibility boundary

This is an x64 per-machine WiX **4.0.6** source/build path. Native MSI compilation,
PowerShell execution and rollback/ACL/WFP/NRPT validation remain required. Linux
source-contract tests do not establish Windows Installer runtime behavior.

## Native prerequisites and pinned tooling

A .NET **runtime alone cannot install/build the WiX tool**. Provision a supported
.NET SDK on the build VM first (WiX 4 uses .NET 6; select a compatible SDK/runtime
combination), MSVC C++ build tools/Windows SDK, Rust and Windows PowerShell 5.1.
WiX and its Util extension are pinned together; the builder rejects a different
WiX version and requests the versioned Util extension:

```powershell
dotnet --list-sdks
dotnet tool install --global wix --version 4.0.6
wix extension add -g WixToolset.Util.wixext/4.0.6
.\scripts\build-windows.ps1
# Only after reviewing the current service's v2/NRPT startup AND offline-release paths:
.\scripts\build-msi.ps1 -Version 0.2.0 -DriverDll C:\assets\wireguard.dll -ConfirmNrptV2Build -Output C:\artifacts\LoVPN-0.2.0.msi
.\scripts\install-client.ps1 -MsiPath C:\artifacts\LoVPN-0.2.0.msi
```

The output directory must exist. All three executables are mandatory. Provide the
official WireGuardNT 1.1 amd64 DLL: its pinned SHA-256 and valid WireGuard LLC
Authenticode signer are checked. No driver is downloaded. The WireGuard license
is packaged. Use increasing three-part versions (major/minor 0–255, build 0–65535).
Do not change UpgradeCode/component GUIDs or relocate the installation directory.

`-ConfirmNrptV2Build` is an explicit **operator attestation**, not a semantic test
of a PE binary. Build from reviewed current source, never point SourceDir at cached
historical binaries. The generated `compatibility.json` contains record schema 2,
NRPT journal capability and the service SHA-256. This binds subsequent wrapper
execution to the reviewed payload but does not prove its implementation correct.
The sidecar manifest is retained next to the output MSI for release inspection.

Sign the reviewed LoVPN executables before building, then sign the MSI using a
trusted code-signing certificate and Windows SDK signtool with trusted timestamping.
Validate signatures separately. Do not modify/re-sign the pinned driver. Signing,
certificates and timestamp infrastructure are not implemented or runtime-tested here;
no credentials are stored in these sources. Review maintenance/support implications
of the pinned historical WiX version before distributing a release.

## Compatibility gate and protection preservation

Windows `session.json` schema 2 can contain a durable `nrpt` restore journal.
Historical binaries can reject this record and unsafe-release protection. Therefore
**an upgrade from an unmarked historical MSI or unmanaged script service is refused**,
even when its current record happens to be schema 1. Allowing it would make the
old MSI's rollback/service-start actions a future hazard after a v2 writer runs.

MSI AppSearch/launch gates run before InstallInitialize/RemoveExistingProducts:
related historical products and existing services require the managed record-v2
registry marker. This marker is introduced only by this compatible packaging line.
It is compatibility metadata, not a security boundary against administrators who
modify registry values, payloads, transforms or manually install historical packages.

The wrapper additionally requires the capability manifest, matching service hash,
expected quoted service ImagePath and readable record schema 1 or 2. It rejects
unknown/malformed/oversized records and NRPT journals attached to schema 1, before
calling **either startup or offline release**. It never downgrades, deletes or
rewrites the journal. Full journal validation/restoration belongs to the reviewed
v2 daemon. Failure must leave protection and restore intent intact.

Historical adoption requires a separately reviewed manual migration with a verified
current recovery binary and a VM backup, not an override flag. Do not use an old
`lovpn-service.exe release`, restore a historical service, or delete `session.json`
to get around an unreadable v2 journal. This packaging has no journal converter.

## Transaction and service recovery

MSI owns installed files, PATH, capability marker and native service registration.
ServiceControl stops/waits before file replacement. ServiceInstall uses LocalSystem
**demand start**, no restart failure actions and **no MSI service-start action**.
Neither a new daemon nor a record writer is deliberately launched in the MSI
transaction. Rollback therefore cannot launch a newly installed daemon as an MSI
start action. Historical MSI rollback is not attempted: its compatibility gate
rejects the upgrade before the old product is removed.

Before an upgrade, the wrapper verifies the existing payload, disables automatic
startup/recovery, stops/waits, and checks the settled record again. After successful
commit with exit 0 it verifies the new payload/record, restores automatic startup
and the 5s/30s/no-action recovery schedule, then starts the service. On failure it
does not restart a restored binary. Investigate the MSI log and compatibility
before manual recovery. Exit 3010 requires reboot/verification; the wrapper does
not enable/start the service against pending file replacements. Direct msiexec
install/repair does not provide the wrapper's post-commit activation checks; run
the wrapper after resolving reboot requirements before expecting automatic service.

MajorUpgrade removes the previous compatible package after InstallInitialize, in
the MSI file/service rollback transaction. **MSI rollback does not reverse daemon
state, NRPT registry changes, DNS/routes or WFP.** It must not be used to justify
future incompatible schema transitions. Compatible package rollback must be tested
while a v2 journal remains pending. Windows rollback-disabled policy, storage loss,
power loss, locked files/reboot and failed recovery remain runtime boundaries.

## State, ACL and explicit release

First installation uses the installer's immediate `UserSID`. An immediate SetProperty
formats the command into `InitializeState`'s **CustomActionData**; deferred SYSTEM
`WixQuietExec` consumes that value rather than reading arbitrary deferred properties.
Run under the intended user's elevation. Alternate-admin/SYSTEM deployment changes
the controlling identity; unattended reassignment is not provided.

Initialization refuses existing unmanaged state and ProgramData/state reparse points.
It creates the directory with an initial protected SYSTEM/Administrators ACL,
checks resulting owner/DACL, then exclusively creates `service.json` (CreateNew).
Existing state ACLs/configuration are never silently rewritten. Validate real ACLs
and concurrent/race behavior in the VM; source checks are not an ACL proof.

State, DPAPI keys, profiles, owner config and logs are not MSI components. Upgrade,
rollback and uninstall retain them. Failed first install can retain initialized
state; reinstall after uninstall refuses that unmanaged retained state. Explicit
reviewed migration is required. DPAPI keys are machine-bound; preserve the same VM.

No MSI action resets/releases firewall or NRPT protection. Plain uninstall retains
filters/journal. Keep a verified **v2-compatible** recovery binary if removing the
product while protection is armed. To deliberately release before uninstall:

```powershell
.\scripts\install-client.ps1 -MsiPath C:\artifacts\LoVPN-0.2.0.msi -Uninstall
.\scripts\install-client.ps1 -MsiPath C:\artifacts\LoVPN-0.2.0.msi -Uninstall -ReleaseFirewall
```

The wrapper checks compatibility, stops the service and runs the verified installed
release command. Failure aborts uninstall. Explicit release is outside the MSI
transaction and **cannot be rolled back**. Automatic purge is refused.

## Checks and required disposable-VM evidence

```powershell
python tests/windows/test_packaging.py
powershell -NoProfile -File tests/windows/test-installer-syntax.ps1
```

Once SDK/WiX are provisioned, compile the actual MSI with the pinned tool/extension,
inspect the CustomAction/InstallExecuteSequence/ServiceControl/ServiceInstall tables,
and execute these scenarios in a snapshotted disposable Windows VM:

1. Fresh install: correct UserSID, protected state ACL/SYSTEM owner, exclusive config,
   quoted service path, post-commit auto/recovery configuration and VPN health.
   Check non-admin, alternate-admin, unmanaged service/state and reparse-path refusal.
2. Historical unmarked MSI/service: upgrade must fail before removal/stop/start or
   state changes, including when v2 has a pending NRPT journal. Ensure old recovery
   is never called. Save independent WFP/NRPT dumps and state/key hashes.
3. Compatible v2 -> newer v2: preserve key/profile/owner hashes and pending NRPT
   intent. Inject malformed/unknown records and a mismatched manifest/service hash;
   wrapper startup/release must refuse without altering protection.
4. Build newer `-TestHooks` MSI. With a compatible prior MSI installed, invoke
   `msiexec /i LoVPN-test.msi LOVPN_TEST_FAIL=1 /qn /norestart /L*v rollback.log`.
   The deferred failure is after StartServices' sequence slot, but **there is no
   start-service action**. Expect 1603 and restored compatible files/registration;
   confirm no new/historical daemon executed and v2 NRPT intent survives. Also test
   through the wrapper using the property set in a test transform. Never distribute
   TestHooks artifacts. Test rollback-disabled policy and locked-file/reboot paths.
5. Plain uninstall keeps WFP/NRPT/key state. Explicit release restores NRPT through
   reviewed service code before removing protection; injected restore/save failure
   must abort uninstall. Check unrelated NRPT/firewall entries remain untouched.
6. Capture physical NIC traffic during upgrade and rollback; inspect independent
   WFP/NRPT snapshots, reboot, then check compatibility and health. Installer success
   and SCM Running do not prove VPN health or no leakage.

The native VM currently has only the .NET runtime, not SDK/WiX. Native compilation,
PowerShell parser execution and these installer/rollback scenarios remain blockers.

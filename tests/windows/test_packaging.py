"""Source-contract checks; these do not execute Windows Installer or prove rollback."""
import pathlib
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
NS = {'w': 'http://wixtoolset.org/schemas/v4/wxs'}


class PackagingContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ET.parse(ROOT / 'packaging/windows/LoVPN.wxs')
        cls.wrapper = (ROOT / 'scripts/install-client.ps1').read_text()

    def test_removal_inside_rollback_transaction(self):
        upgrade = self.tree.find('.//w:MajorUpgrade', NS)
        self.assertEqual(upgrade.attrib['Schedule'], 'afterInstallInitialize')
        self.assertEqual(upgrade.attrib['AllowSameVersionUpgrades'], 'no')

    def test_service_lifecycle_is_native_and_waited(self):
        control = self.tree.find('.//w:ServiceControl', NS).attrib
        self.assertEqual(control['Stop'], 'both')
        self.assertNotIn('Start', control)
        self.assertEqual(control['Wait'], 'yes')
        service = self.tree.find('.//w:ServiceInstall', NS).attrib
        self.assertEqual(service['Arguments'], 'service')
        self.assertEqual(service['Account'], 'LocalSystem')
        self.assertEqual(service['Start'], 'demand')

    def test_state_not_owned_or_removed_by_msi(self):
        for file in self.tree.findall('.//w:File', NS):
            self.assertNotIn('service.json', str(file.attrib))
        self.assertFalse(self.tree.findall('.//w:RemoveFolder', NS))
        self.assertFalse(self.tree.findall('.//w:RemoveFile', NS))
        action = self.tree.find('.//w:Custom[@Action="InitializeState"]', NS)
        self.assertIn('NOT WIX_UPGRADE_DETECTED', action.attrib['Condition'])
        init = (ROOT / 'packaging/windows/Initialize-State.ps1').read_text()
        self.assertLess(init.index('Test-Path -LiteralPath $dir'), init.index('CreateDirectory'))
        self.assertIn('SetAccessRuleProtection($true, $false)', init)

    def test_release_is_explicit_and_checked(self):
        self.assertIn('$ReleaseFirewall -and -not $Uninstall', self.wrapper)
        block = self.wrapper.split('if ($ReleaseFirewall) {', 1)[1].split('$operation =', 1)[0]
        self.assertLess(self.wrapper.index("WaitForStatus('Stopped'"), self.wrapper.index('if ($ReleaseFirewall) {'))
        self.assertLess(block.index('Assert-CompatibleInstallation'), block.index(' release'))
        self.assertIn('$LASTEXITCODE -ne 0', block)
        for action in self.tree.findall('.//w:CustomAction', NS):
            self.assertNotIn(' release', str(action.attrib))

    def test_native_failure_checked_and_reboot_reported(self):
        self.assertIn('$process.ExitCode -notin @(0, 3010)', self.wrapper)
        self.assertIn('$process.ExitCode -eq 3010', self.wrapper)

    def test_driver_supply_chain_build_gate(self):
        build = (ROOT / 'scripts/build-msi.ps1').read_text()
        self.assertIn('b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3', build)
        self.assertIn("$signature.Status -ne 'Valid'", build)
        self.assertIn("CN=WireGuard LLC,*", build)

    def test_historical_upgrade_and_unmanaged_service_refused(self):
        conditions = [node.attrib['Condition'] for node in self.tree.findall('.//w:Launch', NS)]
        self.assertIn('NOT WIX_UPGRADE_DETECTED OR MANAGED_SCHEMA = "2"', conditions)
        self.assertIn('NOT EXISTING_SERVICE OR MANAGED_SCHEMA = "2"', conditions)
        self.assertIn('Historical/unmanaged binary', self.wrapper)
        self.assertIn('$hash -ne $capability.service_sha256', self.wrapper)
        self.assertIn('$session.schema_version -notin @(1, 2)', self.wrapper)
        self.assertIn('$null -ne $session.nrpt -and $session.schema_version -ne 2', self.wrapper)

    def test_deferred_action_receives_explicit_custom_action_data(self):
        setter = self.tree.find('.//w:SetProperty[@Id="InitializeState"]', NS)
        self.assertIn('[UserSID]', setter.attrib['Value'])
        self.assertEqual(setter.attrib['Sequence'], 'execute')
        action = self.tree.find('.//w:CustomAction[@Id="InitializeState"]', NS)
        self.assertEqual(action.attrib['DllEntry'], 'WixQuietExec')
        self.assertEqual(action.attrib['BinaryRef'], 'Wix4UtilCA_X64')
        self.assertNotIn('ExeCommand', action.attrib)

    def test_no_daemon_start_inside_transaction_and_review_gate(self):
        self.assertNotIn('Start-Service', (ROOT / 'packaging/windows/Initialize-State.ps1').read_text())
        success = self.wrapper.index('if (-not $Uninstall -and $process.ExitCode -eq 0)')
        self.assertGreater(self.wrapper.index('Start-Service LoVPNClient'), success)
        self.assertIn("'none/0/none/0/none/0'", self.wrapper)
        build = (ROOT / 'scripts/build-msi.ps1').read_text()
        self.assertIn('if (-not $ConfirmNrptV2Build)', build)
        self.assertIn('WixToolset.Util.wixext/4.0.6', build)
        self.assertIn("^4\\.0\\.6", build)

    def test_acl_and_exclusive_configuration_creation(self):
        init = (ROOT / 'packaging/windows/Initialize-State.ps1').read_text()
        self.assertIn('[IO.FileMode]::CreateNew', init)
        self.assertIn('$actual.AreAccessRulesProtected', init)
        self.assertIn('$actual.GetOwner([Security.Principal.SecurityIdentifier])', init)
        self.assertIn('[IO.FileAttributes]::ReparsePoint', init)


if __name__ == '__main__':
    unittest.main()

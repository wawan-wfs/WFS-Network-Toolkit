"""Static release contract for WeNet; not a Rust build or Windows runtime test."""
from pathlib import Path
import struct
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
def read(path):
    return (ROOT/path).read_text(encoding='utf-8')

class BrandContract(unittest.TestCase):
    def test_binary_names(self):
        self.assertTrue((ROOT/'src/bin/WeNet-Toolkit.rs').is_file())
        self.assertFalse((ROOT/'src/bin/WFS-Network-Toolkit.rs').exists())
        self.assertIn('["WeNet-Toolkit"]', read('build.rs'))
        rc=read('assets/wfs.rc')
        self.assertIn('"OriginalFilename", "WeNet-Toolkit.exe"',rc)
        self.assertIn('"ProductName", "WeNet Toolkit"',rc)
        self.assertIn('"CompanyName", "WFS Project"',rc)
        self.assertIn('assets/WeNet-Toolkit.ico',rc)
        self.assertTrue((ROOT/'src/bin/wfs-netctl.rs').is_file())

    def test_icon_sizes_and_manifest(self):
        data=(ROOT/'assets/WeNet-Toolkit.ico').read_bytes()
        self.assertEqual(struct.unpack_from('<HHH',data),(0,1,7))
        sizes=[]
        for i in range(7):
            w,h,_,_,_,_,n,pos=struct.unpack_from('<BBBBHHII',data,6+16*i)
            sizes.append((w or 256,h or 256))
            png=data[pos:pos+n]
            self.assertEqual(len(png),n)
            self.assertEqual(png[:8],b'\x89PNG\r\n\x1a\n')
            self.assertEqual(struct.unpack_from('>II',png,16),sizes[-1])
        self.assertEqual(sizes,[(n,n) for n in (16,24,32,48,64,128,256)])
        self.assertEqual(data[pos:pos+n],(ROOT/'assets/logo.png').read_bytes())
        ET.fromstring(read('assets/logo.svg'))
        ET.fromstring(read('assets/wfs.manifest'))

    def test_upgrade_contract(self):
        nsi=read('installer/WeNet-Toolkit.nsi')
        for expected in (
            r'InstallDir "$PROGRAMFILES64\WFS Network Toolkit"',
            r'Uninstall\WFSNetworkToolkit" "DisplayName" "WeNet Toolkit"',
            r'Software\WFS\NetworkToolkit\Installer',
            r'WFS Project\WeNet Toolkit.lnk',
            r'Delete "$INSTDIR\WFS-Network-Toolkit.exe"',
        ):
            self.assertIn(expected,nsi)
        self.assertNotIn('RMDir /r',nsi)
        for p in ('src/intelligence/store.rs','src/intelligence/history.rs'):
            self.assertIn('.join("WFS Network Toolkit")',read(p))
        self.assertIn(r'Global\WFS-NetworkToolkit-v1-Mutations',read('src/windows.rs'))

    def test_ui_workflow_and_credit(self):
        ui=read('src/bin/native/toolkit_window.rs')
        self.assertIn('"WeNet Toolkit"',ui)
        self.assertIn('"by WFS Project"',ui)
        self.assertIn('BRAND_TAGLINE',ui)
        workflow=read('.github/workflows/windows.yml')
        # Current authorized CI contract: exactly main push and manual dispatch.
        # Verify the entire top-level trigger/concurrency/permissions section;
        # checking workflow_dispatch alone would silently permit extra events.
        expected = (
            "on:\n"
            "  workflow_dispatch:\n"
            "  push:\n"
            "    branches: [main]\n"
            "concurrency:\n"
            "  group: wenet-windows-${{ github.ref }}\n"
            "  cancel-in-progress: false\n"
            "permissions:\n"
            "  contents: read\n"
        )
        self.assertEqual(workflow.split("\non:\n", 1)[1].split("jobs:\n", 1)[0],
                         expected.removeprefix("on:\n"))
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("scripts/gate_runner.py --out gate-evidence", workflow)
        self.assertIn("BUILD_PROVENANCE.json", workflow)
        self.assertIn("git archive --format=zip", workflow)
        self.assertIn("SHA256SUMS.txt", workflow)
        self.assertNotIn("permissions: write-all", workflow)
        self.assertIn('WeNet-Toolkit.exe',workflow)
        self.assertIn('WeNet-Toolkit.nsi',workflow)
        self.assertNotIn('WFS-Network-Toolkit.exe',workflow)

if __name__ == '__main__':
    unittest.main(verbosity=2)

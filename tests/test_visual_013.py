"""v0.1.3 visual edition regression checks, fully offline."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from wolf_fang import core, vision

class TestVisualEdition(unittest.TestCase):
    def test_inline_art_uses_data_uri(self):
        result = vision.render_dashboard(core.demo_report())
        self.assertIn('data:image/webp;base64,', result)
        self.assertIn('img-src data:', result)
        self.assertIn('WOLF FANG cyber-wolf', result)

    def test_banner_is_valid_webp(self):
        data=vision.embedded_wolf_art().split('base64,')[1].split('"')[0]
        self.assertTrue(base64.b64decode(data).startswith(b'RIFF'))

    def test_local_html_portable_with_no_external_assets(self):
        with tempfile.TemporaryDirectory() as t:
            d=core.save_reports(core.demo_report(),t)
            html=Path(d['html']).read_text(encoding='utf-8')
            self.assertIn('data:image/webp;base64,', html)
            self.assertNotIn('<script',html)
            self.assertNotIn('<link rel="stylesheet"', html)
            self.assertIn('SYNTHETIC',html)

    def test_report_escapes_input_even_with_banner(self):
        r=core.demo_report()
        r['providers']['internetdb']['hostnames']=['<iframe src="https://example.com">']
        html=vision.render_dashboard(r)
        self.assertNotIn('<iframe', html)
        self.assertIn('&lt;iframe',html)

    def test_repo_art_files_exist(self):
        base=Path(vision.__file__).resolve().parent.parent / 'assets'
        for f in ('wolf-fang-emblem.png','wolf-fang-command-center.png','wolf-fang-repo-cover.png'):
            self.assertTrue((base/f).is_file(),f)

if __name__ == '__main__': unittest.main()

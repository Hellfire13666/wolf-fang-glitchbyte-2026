"""Offline FANG VISION v0.1.2 tests. No API requests or secrets."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wolf_fang import core, vision
from wolf_fang.__main__ import main as core_main


class TestFangVision(unittest.TestCase):
    def test_seven_working_sources_are_default(self):
        self.assertEqual(len(core.DEFAULT_PROVIDERS), 7)
        self.assertIn('ipapiis', core.DEFAULT_PROVIDERS)
        self.assertNotIn('greynoise', core.DEFAULT_PROVIDERS)
        self.assertNotIn('abuseipdb', core.DEFAULT_PROVIDERS)
        self.assertNotIn('otx', core.DEFAULT_PROVIDERS)

    def test_old_demo_report_renders_html(self):
        raw = core.demo_report()
        raw['version'] = '0.1.0'
        html = vision.render_dashboard(raw)
        self.assertIn('FANG VISION', html)
        self.assertIn('192.0.2.10', html)
        self.assertIn('SYNTHETIC', html)
        self.assertIn('honeypot-demo', html)

    def test_html_escapes_untrusted_tags(self):
        raw = core.demo_report()
        raw['providers']['internetdb']['hostnames'] = ['<img src=x onerror=alert(1)>']
        raw['provider_status'] = {'danger<script>': {'state':'no_record', 'detail':'<svg onload=x>'}}
        result = vision.render_dashboard(raw)
        self.assertIn('&lt;img', result)
        self.assertIn('&lt;svg', result)
        self.assertNotIn('<img src=x', result)
        self.assertNotIn('<svg onload', result)
        self.assertIn('data-state="no_record"', result)

    def test_csp_local_only_no_external_scripts(self):
        rendered = vision.render_dashboard(core.demo_report())
        self.assertIn("default-src 'none'", rendered)
        self.assertNotIn('<script', rendered)
        self.assertNotIn('cdn.', rendered)

    def test_local_legacy_file_import_preserves_json(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            src = base/'WOLF-FANG-legacy.json'
            src.write_text(json.dumps(core.demo_report()))
            before = src.read_bytes()
            dst = vision.build_from_file(src, base/'vision')
            self.assertEqual(src.read_bytes(), before)
            self.assertIn('FANG VISION', dst.read_text())
            self.assertEqual(dst.stat().st_mode & 0o777, 0o600)
            self.assertEqual((base/'vision').stat().st_mode & 0o777, 0o700)

    def test_not_fang_json_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            src = Path(t)/'wrong.json'
            src.write_text('{"tool":"SOMETHING ELSE","ip":"1.1.1.1"}')
            with self.assertRaises(ValueError):
                vision.build_from_file(src, Path(t)/'out')

    def test_otx_ipv4_adapter_and_no_abuse_claim(self):
        seen = []
        def fake(url, **kwargs):
            seen.append((url,kwargs))
            return {'pulse_info': {'count': 12}, 'reputation': 0, 'country_code': 'AU'}
        with patch.dict(os.environ, {'OTX_API_KEY': 'SECRET_TEST'}, clear=True):
            result = core.otx('1.1.1.1', fetch=fake)
        self.assertIn('/IPv4/1.1.1.1/general', seen[0][0])
        self.assertEqual(seen[0][1]['headers']['X-OTX-API-KEY'], 'SECRET_TEST')
        self.assertEqual(result['pulse_count'], 12)
        self.assertIn('not proof', result['note'])
        self.assertNotIn('SECRET_TEST', str(result))

    def test_otx_ipv6_path(self):
        urls=[]
        def fake(url, **kwargs):
            urls.append(url)
            return {'pulse_info':{}}
        with patch.dict(os.environ, {}, clear=True):
            core.otx('2606:4700:4700::1111', fetch=fake)
        self.assertIn('/IPv6/', urls[0])

    def test_otx_404_becomes_no_record(self):
        with self.assertRaises(core.ProviderNoRecord):
            core.otx('1.1.1.1', fetch=lambda *a, **kw: (_ for _ in ()).throw(core.ProviderHTTPError(404)))

    def test_elapsed_ms_recorded_even_for_provider_failure(self):
        def fails(url, **kwargs):
            raise core.ProviderHTTPError(429)
        with patch('wolf_fang.core.get_json', side_effect=fails):
            data = core.analyze('1.1.1.1', live=True, selected=['otx'], timeout=20)
        self.assertEqual(data['provider_status']['otx']['state'],'rate_limited')
        self.assertIsInstance(data['provider_status']['otx']['elapsed_ms'],float)

    def test_save_reports_writes_dashboard(self):
        with tempfile.TemporaryDirectory() as t:
            paths = core.save_reports(core.demo_report(), t)
            page = Path(paths['html']).read_text()
            self.assertIn('FANG VISION', page)
            self.assertIn('INDEXED PORTS, NOT LIVE', page)
            self.assertTrue(Path(paths['csv']).exists())

    def test_vision_main_offline_latest_report(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t); repdir=base/'reports'; repdir.mkdir()
            (repdir/'WOLF-FANG-192.0.2.10.json').write_text(json.dumps(core.demo_report()))
            result=vision.main(['--reports',str(repdir),'--out',str(base/'out')])
            self.assertEqual(result,0)
            self.assertEqual(len(list((base/'out').glob('*.html'))),1)

    def test_core_default_args_without_live(self):
        with tempfile.TemporaryDirectory() as t:
            with patch('wolf_fang.__main__.save_reports') as saver, patch('wolf_fang.__main__.analyze',return_value=core.demo_report()) as analysis:
                result=core_main(['1.1.1.1','--out',t])
                self.assertEqual(result,0)
                self.assertEqual(len(analysis.call_args.kwargs['selected']),7)
                self.assertEqual(analysis.call_args.kwargs['timeout'],20)


if __name__ == '__main__': unittest.main()

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from wolf_fang.core import (validate_ip, is_public, parse_ports, honeypot_assessment,
    scope_allows, apply_local_feed, demo_report, save_reports, analyze, internetdb,
    ripe, format_console)


class TestWolfFang(unittest.TestCase):
    def test_validate_ipv4_ipv6(self):
        self.assertEqual(str(validate_ip('1.1.1.1')), '1.1.1.1')
        self.assertEqual(validate_ip('2606:4700:4700::1111').version, 6)
        for bad in ('https://example.com', '8.8.8.0/24', 'example.com', 'not-an-ip'):
            with self.assertRaises(ValueError):
                validate_ip(bad)

    def test_public_gate(self):
        self.assertTrue(is_public(validate_ip('1.1.1.1')))
        for ip in ('10.0.0.1', '127.0.0.1', '192.0.2.1', '::1'):
            self.assertFalse(is_public(validate_ip(ip)))

    def test_ports(self):
        self.assertEqual(parse_ports('22,80,22,443'), [22, 80, 443])
        for bad in ('0', '80-90', '65536', 'x', ','.join(map(str, range(1, 19)))):
            with self.assertRaises(ValueError):
                parse_ports(bad)

    def test_scope_gate(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'scope.txt'
            f.write_text('# scope\n192.0.2.10\n')
            self.assertTrue(scope_allows('192.0.2.10', str(f)))
            self.assertFalse(scope_allows('192.0.2.11', str(f)))
            with self.assertRaises(ValueError):
                analyze('192.0.2.11', ports=[443], authorized=True, scope_file=str(f))

    def test_honeypot_tag_only(self):
        result = honeypot_assessment({'internetdb': {'tags': ['honeypot', 'vpn']}})
        self.assertEqual(result['confidence'], 'low')
        self.assertIn('POSSIBLE', result['verdict'])
        negative = honeypot_assessment({'internetdb': {'tags': ['vpn']}})
        self.assertEqual(negative['confidence'], 'none')

    def test_local_analyst_feed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'tags.csv'
            path.write_text('ip,tag,source\n192.0.2.10,honeynet,analyst team\n192.0.2.11,noise,other\n')
            report = demo_report()
            apply_local_feed(report, str(path))
            self.assertEqual(len(report['local_tag_feed']), 1)
            self.assertIn('analyst team', report['honeypot']['evidence'][-1])

    def test_provider_extractors(self):
        def fake(url, **kwargs):
            if 'network-info' in url:
                return {'data': {'prefix': '1.1.1.0/24', 'asns': [13335]}}
            if 'abuse-contact-finder' in url:
                return {'data': {'abuse_contacts': ['abuse@example.invalid']}}
            if 'as-overview' in url:
                return {'data': {'holder': 'Example Holder'}}
            if 'internetdb' in url:
                return {'ports': [443], 'tags': ['vpn'], 'vulns': ['CVE-FAKE']}
            return {}
        self.assertEqual(ripe('1.1.1.1', fake)['origin_asns'], [13335])
        self.assertEqual(internetdb('1.1.1.1', fake)['reported_cves'], ['CVE-FAKE'])

    def test_private_skips_external_calls(self):
        with patch('wolf_fang.core.rdap', side_effect=AssertionError('network call forbidden')):
            report = analyze('10.0.0.1', live=True, selected=['rdap'])
        self.assertEqual(report['providers'], {})
        self.assertFalse(report['public_routable'])

    def test_demo_and_reports(self):
        report = demo_report()
        self.assertIn('SYNTHETIC', format_console(report, color=False))
        with tempfile.TemporaryDirectory() as d:
            paths = save_reports(report, d)
            for file in paths.values():
                self.assertTrue(Path(file).exists())
            self.assertIn('SYNTHETIC DEMO', Path(paths['html']).read_text())


if __name__ == '__main__':
    unittest.main()

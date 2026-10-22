"""WOLF FANG v0.1.1 provider reliability and security regression tests; offline."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from wolf_fang import core


class TestUpgrade(unittest.TestCase):
    def test_greynoise_404_is_unobserved(self):
        def missing(_url, **_kwargs):
            raise core.ProviderHTTPError(404)
        with self.assertRaises(core.ProviderNoRecord):
            core.greynoise('1.1.1.1', fetch=missing)

    def test_greynoise_notfound_not_error_in_report(self):
        def simulated(_url, **_kwargs):
            raise core.ProviderHTTPError(404)
        with patch('wolf_fang.core.get_json', side_effect=simulated), patch('wolf_fang.core.time.sleep'):
            result = core.analyze('1.1.1.1', live=True, selected=['greynoise'], timeout=2)
        self.assertEqual(result['provider_status']['greynoise']['state'], 'no_record')
        self.assertNotIn('greynoise', result['provider_errors'])
        self.assertEqual(result['honeypot']['confidence'], 'none')

    def test_internetdb_404_means_no_index(self):
        with self.assertRaises(core.ProviderNoRecord):
            core.internetdb('1.1.1.1', fetch=lambda *_a, **_kw: (_ for _ in ()).throw(core.ProviderHTTPError(404)))

    def test_rate_limit_does_not_retry(self):
        calls = []
        def simulated(url, **kwargs):
            calls.append(url)
            raise core.ProviderHTTPError(429)
        with patch('wolf_fang.core.get_json', side_effect=simulated):
            result = core.analyze('1.1.1.1', live=True, selected=['greynoise'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['provider_status']['greynoise']['state'], 'rate_limited')

    def test_timeout_reaches_fetch(self):
        kwargs_seen = []
        def simulated(url, **kwargs):
            kwargs_seen.append(kwargs)
            return {'ports': [443], 'hostnames': [], 'cpes': [], 'tags': [], 'vulns': []}
        with patch('wolf_fang.core.get_json', side_effect=simulated):
            core.analyze('1.1.1.1', live=True, selected=['internetdb'], timeout=3.25)
        self.assertEqual(kwargs_seen[0]['timeout'], 3.25)

    def test_api_not_configured_is_not_failure(self):
        with patch.dict(os.environ, {}, clear=True):
            result = core.analyze('1.1.1.1', live=True, selected=['abuseipdb'])
        self.assertEqual(result['provider_status']['abuseipdb']['state'], 'not_configured')
        self.assertFalse(result['provider_errors'])

    def test_ipapiis_anonymous_shape(self):
        result = core.ipapiis('1.1.1.1', fetch=lambda _url: {
            'ip': '1.1.1.1', 'company': 'Example Network', 'asn': 'AS123 Example',
            'city': 'Remote City', 'country': 'Example', 'is_bogon': False})
        self.assertEqual(result['asn'], 'AS123 Example')
        self.assertIs(result['security_flags_available'], False)
        self.assertNotIn('is_vpn', result)

    def test_ripestatus_summary(self):
        sample = {'status': 'ok', 'data': {'query_time': '2026-10-21',
            'visibility': {'v4': {'ris_peers_seeing': 10, 'total_ris_peers': 20}}}}
        result = core.ripestatus('1.1.1.1', fetch=lambda _url: sample)
        self.assertEqual(result['visibility']['v4']['ris_peers_seeing'], 10)
        self.assertIn('not direct', result['note'])

    def test_no_secret_in_report(self):
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'TEST_SECRET_HIDDEN'}):
            def simulated(_url, **_kw):
                raise core.ProviderHTTPError(401)
            with patch('wolf_fang.core.get_json', side_effect=simulated):
                result = core.analyze('1.1.1.1', live=True, selected=['abuseipdb'])
            serialized = str(result)
            self.assertNotIn('TEST_SECRET_HIDDEN', serialized)
            self.assertEqual(result['provider_status']['abuseipdb']['state'], 'authentication_error')

    def test_report_writes_status(self):
        with tempfile.TemporaryDirectory() as path:
            report = core.demo_report()
            report['provider_status'] = {'greynoise': {'state':'no_record'}}
            locations = core.save_reports(report, path)
            self.assertIn('no_record', Path(locations['html']).read_text())
            self.assertIn('no_record', Path(locations['csv']).read_text())
            self.assertIn('no_record', Path(locations['json']).read_text())


if __name__ == '__main__':
    unittest.main()

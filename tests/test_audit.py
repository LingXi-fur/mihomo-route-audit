import copy
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import quote

import mihomo_route_audit as audit


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "examples/policy.example.json"
SNAPSHOT_PATH = ROOT / "examples/snapshot.example.json"


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(POLICY_PATH.read_text())
        self.runtime = json.loads(SNAPSHOT_PATH.read_text())

    def run_cli(self, *args, policy=POLICY_PATH):
        return subprocess.run([sys.executable, str(ROOT / 'mihomo_route_audit.py'),
                               '--policy', str(policy), *map(str, args)],
                              capture_output=True, text=True, check=False, timeout=10)

    def test_offline_pass(self):
        result = self.run_cli('--snapshot', SNAPSHOT_PATH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            'status': 'PASS', 'mode': 'snapshot', 'rules_checked': 2, 'failures': [],
        })

    def test_clean_output_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.json'
            self.runtime['group']['all'].append('private-fallback-name')
            self.runtime['rules']['rules'][1]['extra']['disabled'] = True
            path.write_text(json.dumps(self.runtime))
            result = self.run_cli('--snapshot', path)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('private-fallback-name', result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['failures'], [
            {'code': 'GROUP_MEMBERS_MISMATCH'}, {'code': 'RULE_DISABLED', 'position': 2},
        ])

    def test_route_deviations(self):
        cases = [
            ('higher priority rule', lambda data: data['rules']['rules'].insert(0, {'type': 'Match'}),
             'RULE_MISMATCH'),
            ('wrong route', lambda data: data['rules']['rules'][0].update(proxy='DIRECT'), 'RULE_MISMATCH'),
            ('missing rule', lambda data: data['rules'].update(rules=[]), 'RULE_MISSING'),
            ('unknown rule state', lambda data: data['rules']['rules'][0].pop('extra'), 'RULE_STATE_UNKNOWN'),
            ('different selection', lambda data: data['group'].update(now='Another proxy'), 'SELECTED_NODE_MISMATCH'),
            ('nested group', lambda data: data['node'].update(all=['Other']), 'NODE_NOT_CONFIRMED_LEAF'),
            ('direct alias', lambda data: data['node'].update(type='Direct'), 'NODE_NOT_PROXY'),
            ('chained proxy', lambda data: data['node'].update({'dialer-proxy': 'Other'}), 'NODE_USES_DIALER_PROXY'),
            ('no process rules', lambda data: data['configs'].update({'find-process-mode': 'off'}),
             'PROCESS_MATCHING_UNAVAILABLE'),
            ('global mode', lambda data: data['configs'].update(mode='global'), 'MODE_MISMATCH'),
            ('tun differs', lambda data: data['configs']['tun'].update(enable=True), 'TUN_MISMATCH'),
        ]
        for name, mutate, code in cases:
            with self.subTest(name=name):
                runtime = copy.deepcopy(self.runtime)
                mutate(runtime)
                self.assertIn(code, {item['code'] for item in audit.evaluate(self.policy, runtime)})

    def test_duplicate_key_stops_before_socket_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text('{"group":"same","group":"different"}')
            result = self.run_cli('--socket', Path(directory) / 'missing.sock', policy=path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['code'], 'DUPLICATE_JSON_KEY')

    def test_live_http_uses_only_read_routes_and_rejects_socket_symlink(self):
        group = 'Example Québec'
        self.policy['group'] = group
        self.runtime['group']['name'] = group
        for row in self.runtime['rules']['rules'][:2]:
            row['proxy'] = group
        replies = {
            '/configs': self.runtime['configs'], '/rules': self.runtime['rules'],
            '/proxies/' + quote(group, safe=''): self.runtime['group'],
            '/proxies/' + quote(self.policy['node'], safe=''): self.runtime['node'],
        }
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command, self.path))
                self.send_response(200 if self.path in replies else 404)
                self.end_headers()
                self.wfile.write(json.dumps(replies.get(self.path, {})).encode())

            def log_message(self, format, *args):
                pass

        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            path = Path(directory) / 'controller'
            policy = Path(directory) / 'policy.json'
            policy.write_text(json.dumps(self.policy))
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with socketserver.UnixStreamServer(str(path), Handler) as server:
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    result = self.run_cli('--socket', path, policy=policy)
                    rejected = self.run_cli('--socket', alias, policy=policy)
                finally:
                    server.shutdown()
                    worker.join()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(requests, [('GET', route) for route in replies])
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(json.loads(rejected.stdout)['code'], 'EXPECTED_OWNED_UNIX_SOCKET')

    def test_bounded_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            with path.open('wb') as source:
                source.truncate(audit.MAX_POLICY + 1)
            result = self.run_cli('--snapshot', SNAPSHOT_PATH, policy=path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['code'], 'INPUT_TOO_LARGE')

    def test_bounded_controller_response(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b' ' * (audit.MAX_POLICY + 1))

            def log_message(self, format, *args):
                pass

        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            path = Path(directory) / 'controller'
            with socketserver.UnixStreamServer(str(path), Handler) as server:
                worker = threading.Thread(target=server.handle_request, daemon=True)
                worker.start()
                result = self.run_cli('--socket', path)
                worker.join(timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['code'], 'CONTROLLER_RESPONSE_TOO_LARGE')


if __name__ == '__main__':
    unittest.main()

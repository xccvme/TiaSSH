"""Installer transactional behavior tests with sandboxed command mocks."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[2] / 'server/install-server.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        scratch = '/root/.hermes/cache/scratch'
        self.tmp = tempfile.TemporaryDirectory(prefix='installer-test-', dir=scratch)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()

        self.src = self.root / 'source'
        self.src.mkdir()
        shutil.copy2(INSTALLER, self.src / 'install-server.sh')
        (self.src / 'server.js').write_text('new-app')
        (self.src / 'admin-recovery.js').write_text('stub')
        (self.src / 'package.json').write_text('{}')
        (self.src / 'data').mkdir()
        (self.src / 'data' / 'source-only').write_text('must-not-copy')
        (self.src / 'node_modules').mkdir()
        (self.src / 'node_modules' / 'source-module').write_text('must-not-copy')

        self.app = self.root / 'app'
        self.old = self.app / 'server'
        self.old.mkdir(parents=True)
        (self.old / 'server.js').write_text('old-app')
        (self.old / 'admin-recovery.js').write_text('old-stub')
        (self.old / 'package.json').write_text('{}')
        (self.old / 'data').mkdir()
        for name, text in {
            'tiassh.db': 'db',
            'tiassh.db-wal': 'wal',
            'tiassh.db-shm': 'shm',
            'master.key': 'master',
            'recovery.ready': 'has-key',
        }.items():
            (self.old / 'data' / name).write_text(text)

        self.units = self.root / 'units'
        self.units.mkdir()
        self.unit = self.units / 'tiassh.service'
        self.unit.write_text('old-unit')

        self.log = self.root / 'calls.log'
        self.env = dict(
            os.environ,
            PATH=f"{self.bin}:/usr/bin:/bin",
            APP_DIR=str(self.app),
            SYSTEMD_DIR=str(self.units),
            MOCK_LOG=str(self.log),
            MOCK_UID='0',
            MOCK_NODE_VERSION='v24.2.0',
            MOCK_ACTIVE='1',
            HEALTH_RETRIES='1',
            HEALTH_DELAY_SEC='0',
        )

        self._mock('id', 'echo "${MOCK_UID:-0}"')
        self._mock('npm', 'echo "npm" >> "$MOCK_LOG"; [ "${FAIL_NPM:-0}" = 1 ] && exit 12; mkdir -p node_modules; echo ok > node_modules/installed')
        self._mock(
            'systemctl',
            'echo "systemctl $*" >> "$MOCK_LOG"\n'
            'case "$1" in\n'
            '  is-active) [ "${MOCK_ACTIVE:-0}" = 1 ]; exit $? ;;\n'
            '  restart) [ "${FAIL_RESTART:-0}" = 1 ] && exit 13 || exit 0 ;;\n'
            '  stop) [ "${FAIL_STOP:-0}" = 1 ] && exit 14 || exit 0 ;;\n'
            'esac\n'
            'exit 0',
        )
        self._mock('curl', 'echo "curl" >> "$MOCK_LOG"; [ "${FAIL_HEALTH:-0}" = 1 ] && echo "{\"ok\":false}" || echo "{\"ok\":true,\"name\":\"tiassh-sync\"}"')
        self._mock('hostname', 'echo "198.51.100.24 10.0.0.5"')
        self._mock('sleep', 'exit 0')
        self._mock('cp', '/bin/cp "$@"')
        self._mock('mv', '/bin/mv "$@"')
        self._mock('rm', '/bin/rm "$@"')
        self._mock('tar', '/bin/tar "$@"')
        self._mock('mkdir', '/bin/mkdir "$@"')
        self._mock('mktemp', '/usr/bin/mktemp "$@"')

        self._mock(
            'node',
            'if [ "${MOCK_NODE_MISSING:-0}" = 1 ]; then exit 127; fi\n'
            'if [ "$1" = "--version" ] || [ "$1" = "-v" ]; then\n'
            '  printf "%s\\n" "${MOCK_NODE_VERSION:-v24.2.0}"; exit 0;\n'
            'fi\n'
            'if [ "$1" = "-e" ]; then\n'
            '  code="$2"; arg="$3"\n'
            '  case "$code" in\n'
            '    *recovery_keys*) [ -f "$(dirname "$arg")/recovery.ready" ] && exit 0 || exit 1 ;;\n'
            '    *JSON.parse*) [ "$arg" = "{\"ok\":true,\"name\":\"tiassh-sync\"}" ] && exit 0 || exit 1 ;;\n'
            '  esac\n'
            '  exit 0\n'
            'fi\n'
            'if [ "$1" = "admin-recovery.js" ] && [ "$2" = "init" ]; then\n'
            '  echo "admin-recovery init" >> "$MOCK_LOG"\n'
            '  [ -n "${DATA_DIR:-}" ] || exit 33\n'
            '  mkdir -p "$DATA_DIR"\n'
            '  echo generated > "$DATA_DIR/recovery.ready"\n'
            '  exit 0\n'
            'fi\n'
            'echo "unexpected node invocation: $*" >&2\n'
            'exit 99',
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _mock(self, name: str, body: str):
        path = self.bin / name
        path.write_text('#!/bin/bash\nset -eu\n' + body + '\n')
        path.chmod(0o755)

    def run_install(self, script=None, **extra_env):
        return subprocess.run(
            ['/bin/bash', str(script or self.src / 'install-server.sh')],
            env=dict(self.env, **extra_env),
            text=True,
            capture_output=True,
            timeout=20,
        )

    def read_log(self):
        return self.log.read_text() if self.log.exists() else ''

    def assert_data_intact(self):
        for name, expected in {
            'tiassh.db': 'db',
            'tiassh.db-wal': 'wal',
            'tiassh.db-shm': 'shm',
            'master.key': 'master',
            'recovery.ready': 'has-key',
        }.items():
            self.assertEqual((self.old / 'data' / name).read_text(), expected)

    def test_prerequisites_fail_without_mutation(self):
        for env in (
            dict(MOCK_UID='1000'),
            dict(MOCK_NODE_VERSION='v22.13.0'),
            dict(MOCK_NODE_MISSING='1'),
        ):
            result = self.run_install(**env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
            self.assert_data_intact()
            self.assertEqual(self.read_log(), '')

    def test_same_source_deploy_preserves_existing_data_and_skips_source_node_modules(self):
        shutil.copy2(INSTALLER, self.old / 'install-server.sh')
        result = self.run_install(self.old / 'install-server.sh', PUBLIC_URL='https://pub.example', WEB_ORIGIN='https://portal.example')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assert_data_intact()
        self.assertTrue((self.old / 'node_modules' / 'installed').exists())
        self.assertFalse((self.old / 'data' / 'source-only').exists())
        self.assertFalse((self.old / 'node_modules' / 'source-module').exists())
        unit = self.unit.read_text()
        self.assertIn(f'WorkingDirectory={self.old}', unit)
        self.assertIn('Environment=PUBLIC_URL=https://pub.example', unit)
        self.assertIn('Environment=WEB_ORIGIN=https://portal.example', unit)

    def test_install_dependency_failure_keeps_existing_release_untouched(self):
        result = self.run_install(FAIL_NPM='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assert_data_intact()
        self.assertEqual(self.unit.read_text(), 'old-unit')

    def test_stop_failure_never_copies_live_database(self):
        result = self.run_install(FAIL_STOP='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assert_data_intact()
        self.assertEqual(self.unit.read_text(), 'old-unit')

    def test_failed_stage_move_restores_old_release(self):
        self._mock('mv', 'case "$1" in *stage) exit 44 ;; esac\nif [ "$1" = -- ]; then case "$2" in *stage) exit 44 ;; esac; fi\n/bin/mv "$@"')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assert_data_intact()
        self.assertEqual(self.unit.read_text(), 'old-unit')

    def test_invalid_configuration_is_rejected_before_deployment(self):
        for config in [dict(PORT='bad'), dict(PUBLIC_URL='file:///etc'), dict(APP_DIR='/'), dict(PUBLIC_URL='https://example.test\nEnvironment=EVIL=yes')]:
            result = self.run_install(**config)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.read_log(), '')
            self.assert_data_intact()

    def test_copy_failure_preserves_original_data(self):
        self._mock('cp', 'case "$*" in *data*) exit 45 ;; esac\n/bin/cp "$@"')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assert_data_intact()
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assertEqual(self.unit.read_text(), 'old-unit')

    def test_nested_runtime_data_is_excluded(self):
        nested = self.src / 'nested/data'; nested.mkdir(parents=True)
        (nested / 'secret').write_text('secret')
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.old / 'nested/data').exists())

    def test_non_tty_first_deploy_without_recovery_key_fails_with_instruction(self):
        shutil.rmtree(self.old)
        self.app.mkdir(parents=True, exist_ok=True)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('recovery key', (result.stderr + result.stdout).lower())
        self.assertIn('admin-recovery.js init', (result.stderr + result.stdout))
        self.assertNotIn('admin-recovery init', self.read_log())

    def test_restart_failure_rolls_back_code_data_and_unit(self):
        result = self.run_install(FAIL_RESTART='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assert_data_intact()
        self.assertEqual(self.unit.read_text(), 'old-unit')

    def test_health_failure_rolls_back_and_reports_failure(self):
        result = self.run_install(FAIL_HEALTH='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('health', (result.stderr + result.stdout).lower())
        self.assertEqual((self.old / 'server.js').read_text(), 'old-app')
        self.assert_data_intact()


if __name__ == '__main__':
    unittest.main(verbosity=2)

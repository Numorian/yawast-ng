import sys
import types
from unittest import TestCase, mock

import yawast.scanner.plugins.plugin_manager as plugin_manager
from tests import utils


class TestPluginLoader(TestCase):
    def make_fake_plugin_base(self, name, base):
        return type(name, (base,), {})

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.importlib.import_module")
    @mock.patch("yawast.scanner.plugins.plugin_manager.pkg_resources")
    def test_load_plugins_scanner_plugin(
        self, mock_pkg_resources, mock_import_module, mock_output
    ):
        # Setup fake plugin class
        FakeScannerPlugin = self.make_fake_plugin_base(
            "FakeScannerPlugin", plugin_manager.ScannerPluginBase
        )

        # Setup fake entry point
        fake_entry_point = mock.Mock()
        fake_entry_point.name = "fake_scanner"
        fake_entry_point.load.return_value = FakeScannerPlugin

        # Setup pkg_resources
        mock_pkg_resources.working_set.by_key = {
            "yawast_plugin_test": None,
            "other_package": None,
        }
        mock_pkg_resources.iter_entry_points.return_value = [fake_entry_point]

        # Setup import_module to return a module with entry_points
        fake_module = types.SimpleNamespace(entry_points=True)
        mock_import_module.return_value = fake_module

        # Clear plugins dict
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Assert plugin loaded as scanner
        assert "fake_scanner" in plugin_manager.plugins["scanner"]
        assert plugin_manager.plugins["scanner"]["fake_scanner"] is FakeScannerPlugin

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.importlib.import_module")
    @mock.patch("yawast.scanner.plugins.plugin_manager.pkg_resources")
    def test_load_plugins_hook_plugin(
        self, mock_pkg_resources, mock_import_module, mock_output
    ):
        # Setup fake plugin class
        FakeHookPlugin = self.make_fake_plugin_base(
            "FakeHookPlugin", plugin_manager.HookScannerBase
        )

        # Setup entry point
        fake_entry_point = mock.Mock()
        fake_entry_point.name = "fake_hook"
        fake_entry_point.load.return_value = FakeHookPlugin

        # Setup pkg_resources
        mock_pkg_resources.working_set.by_key = {
            "yawast_plugin_hook": None,
        }
        mock_pkg_resources.iter_entry_points.return_value = [fake_entry_point]

        # Setup import_module to return a module with entry_points
        fake_module = types.SimpleNamespace(entry_points=True)
        mock_import_module.return_value = fake_module

        # Clear plugins dict
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Assert plugin loaded as hook
        assert "fake_hook" in plugin_manager.plugins["hook"]
        assert plugin_manager.plugins["hook"]["fake_hook"] is FakeHookPlugin

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.importlib.import_module")
    @mock.patch("yawast.scanner.plugins.plugin_manager.pkg_resources")
    def test_load_plugins_non_plugin_class(
        self, mock_pkg_resources, mock_import_module, mock_output
    ):
        # Setup fake class not inheriting from PluginBase
        class NotAPlugin:
            pass

        fake_entry_point = mock.Mock()
        fake_entry_point.name = "not_a_plugin"
        fake_entry_point.load.return_value = NotAPlugin

        mock_pkg_resources.working_set.by_key = {
            "yawast_plugin_invalid": None,
        }
        mock_pkg_resources.iter_entry_points.return_value = [fake_entry_point]

        fake_module = types.SimpleNamespace(entry_points=True)
        mock_import_module.return_value = fake_module

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Should not be loaded
        assert "not_a_plugin" not in plugin_manager.plugins["scanner"]
        assert "not_a_plugin" not in plugin_manager.plugins["hook"]

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.importlib.import_module")
    @mock.patch("yawast.scanner.plugins.plugin_manager.pkg_resources")
    def test_load_plugins_import_error(
        self, mock_pkg_resources, mock_import_module, mock_output
    ):
        mock_pkg_resources.working_set.by_key = {
            "yawast_plugin_broken": None,
        }
        mock_import_module.side_effect = Exception("Import failed")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        with utils.capture_sys_output() as (stdout, stderr):
            plugin_manager.load_plugins()

            self.assertIn(
                "Failed to load package yawast_plugin_broken: Import failed",
                stdout.getvalue(),
            )

        assert not plugin_manager.plugins["scanner"]
        assert not plugin_manager.plugins["hook"]

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.importlib.import_module")
    @mock.patch("yawast.scanner.plugins.plugin_manager.pkg_resources")
    def test_load_plugins_no_entry_points(
        self, mock_pkg_resources, mock_import_module, mock_output
    ):
        mock_pkg_resources.working_set.by_key = {
            "yawast_plugin_noentry": None,
        }
        fake_module = types.SimpleNamespace()
        mock_import_module.return_value = fake_module

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Should not call iter_entry_points or debug
        mock_output.debug.assert_not_called()

    @mock.patch("builtins.print")
    def test_print_loaded_plugins_with_plugins(self, mock_print):
        # Setup fake plugin classes
        class FakeScannerPlugin(plugin_manager.ScannerPluginBase):
            pass

        class FakeHookPlugin(plugin_manager.HookScannerBase):
            pass

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()
        plugin_manager.plugins["scanner"]["scanner1"] = FakeScannerPlugin
        plugin_manager.plugins["hook"]["hook1"] = FakeHookPlugin

        plugin_manager.print_loaded_plugins()

        # Check that print was called with expected output
        expected_calls = [
            mock.call("Loaded scanner plugins:"),
            mock.call(f" - scanner1: {FakeScannerPlugin.__name__}"),
            mock.call("Loaded hook plugins:"),
            mock.call(f" - hook1: {FakeHookPlugin.__name__}"),
            mock.call(),
        ]
        mock_print.assert_has_calls(expected_calls, any_order=False)

    @mock.patch("builtins.print")
    def test_print_loaded_plugins_no_plugins(self, mock_print):
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.print_loaded_plugins()

        # Should print headers and a blank line, but no plugins
        expected_calls = [
            mock.call("Loaded scanner plugins:"),
            mock.call("Loaded hook plugins:"),
            mock.call(),
        ]
        mock_print.assert_has_calls(expected_calls, any_order=False)

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_http_scans_runs_non_http_plugins(self, mock_output):
        # Setup a plugin that does NOT inherit from HttpScannerPluginBase
        class FakeScanner(plugin_manager.ScannerPluginBase):
            def __init__(self):
                self.checked = False

            def check(self):
                self.checked = True
                mock_output.debug("checked")

        fake_plugin = FakeScanner
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["fake"] = fake_plugin

        plugin_manager.run_http_scans()

        # Should call check and output.debug for start and completion
        mock_output.debug.assert_any_call("Running scanner plugins...")
        mock_output.debug.assert_any_call("Plugin fake completed successfully.")
        # Should not call output.error
        mock_output.error.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_http_scans_skips_http_plugins(self, mock_output):
        # Setup a plugin that DOES inherit from HttpScannerPluginBase
        class FakeHttpScanner(plugin_manager.HttpScannerPluginBase):
            def check(self):
                raise Exception("Should not be called")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["http"] = FakeHttpScanner

        plugin_manager.run_http_scans()

        # Should not call check, so no error
        mock_output.error.assert_not_called()
        mock_output.debug.assert_any_call("Running scanner plugins...")

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_http_scans_handles_plugin_exception(self, mock_output):
        # Setup a plugin that raises in check
        class FailingScanner(plugin_manager.ScannerPluginBase):
            def check(self):
                raise ValueError("fail!")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["fail"] = FailingScanner

        plugin_manager.run_http_scans()

        # Should call output.error with the exception message
        mock_output.error.assert_any_call(
            mock.ANY  # message includes "Failed to run plugin fail: fail!"
        )
        # Should not call debug for completion
        calls = [c[0][0] for c in mock_output.debug.call_args_list]
        assert not any(
            "completed successfully" in call for call in calls if "fail" in call
        )

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_http_scans_no_scanner_plugins(self, mock_output):
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.run_http_scans()
        # Should not call output.debug or output.error
        mock_output.debug.assert_not_called()
        mock_output.error.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_network_scans_runs_network_plugins(self, mock_output):
        # Setup a plugin that DOES inherit from NetworkScannerPluginBase
        class FakeNetworkScanner(plugin_manager.NetworkScannerPluginBase):
            def __init__(self):
                self.checked = False

            def check(self):
                self.checked = True
                mock_output.debug("checked network")

        fake_plugin = FakeNetworkScanner
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["net"] = fake_plugin

        plugin_manager.run_network_scans()

        # Should call check and output.debug for start and completion
        mock_output.debug.assert_any_call("Running network scanner plugins...")
        mock_output.debug.assert_any_call("Plugin net completed successfully.")
        mock_output.error.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_network_scans_skips_non_network_plugins(self, mock_output):
        # Setup a plugin that does NOT inherit from NetworkScannerPluginBase
        class FakeScanner(plugin_manager.ScannerPluginBase):
            def check(self):
                raise Exception("Should not be called")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["not_net"] = FakeScanner

        plugin_manager.run_network_scans()

        # Should not call check, so no error
        mock_output.error.assert_not_called()
        mock_output.debug.assert_any_call("Running network scanner plugins...")

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_network_scans_handles_plugin_exception(self, mock_output):
        # Setup a plugin that raises in check
        class FailingNetworkScanner(plugin_manager.NetworkScannerPluginBase):
            def check(self):
                raise ValueError("fail net!")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["fail_net"] = FailingNetworkScanner

        plugin_manager.run_network_scans()

        # Should call output.error with the exception message
        mock_output.error.assert_any_call(
            mock.ANY  # message includes "Failed to run plugin fail_net: fail net!"
        )
        # Should not call debug for completion for the failing plugin
        calls = [c[0][0] for c in mock_output.debug.call_args_list]
        assert not any(
            "completed successfully" in call for call in calls if "fail_net" in call
        )

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_network_scans_no_scanner_plugins(self, mock_output):
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.run_network_scans()
        # Should not call output.debug or output.error
        mock_output.debug.assert_not_called()
        mock_output.error.assert_not_called()

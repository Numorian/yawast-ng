import sys
import types
from unittest import TestCase, mock

import yawast.scanner.plugins.plugin_manager as plugin_manager
from tests import utils


class TestPluginLoader(TestCase):
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
        unexpected_calls = [
            mock.call("Loaded scanner plugins:"),
            mock.call("Loaded hook plugins:"),
        ]

        # make sure no unexpected calls were made
        for call in unexpected_calls:
            assert call not in mock_print.call_args_list

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_http_scans_handles_plugin_exception(self, mock_output):
        # Setup a plugin that raises in check
        class FailingScanner(plugin_manager.HttpScannerPluginBase):
            def check(self, url):
                raise ValueError("fail!")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["fail"] = FailingScanner

        plugin_manager.run_http_scans("https://example.com")

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
        plugin_manager.run_http_scans("https://example.com")
        # Should not call output.debug or output.error
        mock_output.debug.assert_not_called()
        mock_output.error.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_network_scans_runs_network_plugins(self, mock_output):
        # Setup a plugin that DOES inherit from NetworkScannerPluginBase
        class FakeNetworkScanner(plugin_manager.NetworkScannerPluginBase):
            def __init__(self):
                self.checked = False

            def check(self, url):
                self.checked = True
                mock_output.debug("checked network")

        fake_plugin = FakeNetworkScanner
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["net"] = fake_plugin

        plugin_manager.run_network_scans("https://example.com")

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

        plugin_manager.run_network_scans("https://example.com")

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

        plugin_manager.run_network_scans("https://example.com")

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
        plugin_manager.run_network_scans("https://example.com")
        # Should not call output.debug or output.error
        mock_output.debug.assert_not_called()
        mock_output.error.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.entry_points")
    def test_load_plugins_loads_scanner_and_hook_plugins(
        self, mock_entry_points, mock_output
    ):
        # Setup fake plugin classes
        class FakeScannerPlugin(plugin_manager.ScannerPluginBase):
            pass

        class FakeHookPlugin(plugin_manager.HookScannerBase):
            pass

        # Setup fake entry points
        fake_scanner_ep = mock.Mock()
        fake_scanner_ep.name = "scanner_plugin"
        fake_scanner_ep.load.return_value = FakeScannerPlugin

        fake_hook_ep = mock.Mock()
        fake_hook_ep.name = "hook_plugin"
        fake_hook_ep.load.return_value = FakeHookPlugin

        mock_entry_points.return_value = [fake_scanner_ep, fake_hook_ep]

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Scanner plugin should be loaded under "scanner"
        assert "scanner_plugin" in plugin_manager.plugins["scanner"]
        assert plugin_manager.plugins["scanner"]["scanner_plugin"] is FakeScannerPlugin

        # Hook plugin should be loaded under "hook"
        assert "hook_plugin" in plugin_manager.plugins["hook"]
        assert plugin_manager.plugins["hook"]["hook_plugin"] is FakeHookPlugin

        # Debug output should be called for both
        mock_output.debug.assert_any_call("Loaded plugin: scanner_plugin (scanner)")
        mock_output.debug.assert_any_call("Loaded plugin: hook_plugin (hook)")

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.entry_points")
    def test_load_plugins_skips_non_pluginbase(self, mock_entry_points, mock_output):
        # Setup a class that does not inherit from PluginBase
        class NotAPlugin:
            pass

        fake_ep = mock.Mock()
        fake_ep.name = "not_a_plugin"
        fake_ep.load.return_value = NotAPlugin

        mock_entry_points.return_value = [fake_ep]

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Should not be loaded
        assert "not_a_plugin" not in plugin_manager.plugins["scanner"]
        assert "not_a_plugin" not in plugin_manager.plugins["hook"]
        mock_output.debug.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.entry_points")
    def test_load_plugins_handles_load_exception(self, mock_entry_points, mock_output):
        fake_ep = mock.Mock()
        fake_ep.name = "bad_plugin"
        fake_ep.load.side_effect = RuntimeError("load failed")

        mock_entry_points.return_value = [fake_ep]

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Should not be loaded
        assert "bad_plugin" not in plugin_manager.plugins["scanner"]
        assert "bad_plugin" not in plugin_manager.plugins["hook"]
        # Should call output.error
        mock_output.error.assert_any_call(mock.ANY)
        mock_output.debug.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    @mock.patch("yawast.scanner.plugins.plugin_manager.entry_points")
    def test_load_plugins_handles_issubclass_exception(
        self, mock_entry_points, mock_output
    ):
        # Setup a plugin whose issubclass check will fail (not a class)
        fake_ep = mock.Mock()
        fake_ep.name = "broken_plugin"
        fake_ep.load.return_value = object()  # not a class

        mock_entry_points.return_value = [fake_ep]

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["hook"].clear()

        plugin_manager.load_plugins()

        # Should not be loaded
        assert "broken_plugin" not in plugin_manager.plugins["scanner"]
        assert "broken_plugin" not in plugin_manager.plugins["hook"]
        # Should call output.error
        mock_output.error.assert_any_call(mock.ANY)
        mock_output.debug.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_other_scans_runs_other_plugins(self, mock_output):
        # Setup a plugin that inherits from ScannerPluginBase but not Http/Network
        class FakeOtherScanner(plugin_manager.ScannerPluginBase):
            def __init__(self):
                self.checked = False

            def check(self, url):
                self.checked = True
                mock_output.debug("checked other")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["other"] = FakeOtherScanner

        plugin_manager.run_other_scans("https://example.com")

        # Should call check and output.debug for start and completion
        mock_output.debug.assert_any_call("Running other scanner plugins...")
        mock_output.debug.assert_any_call("Plugin other completed successfully.")
        mock_output.error.assert_not_called()

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_other_scans_skips_http_and_network_plugins(self, mock_output):
        class FakeHttpScanner(plugin_manager.HttpScannerPluginBase):
            def check(self, url):
                raise Exception("Should not be called")

        class FakeNetworkScanner(plugin_manager.NetworkScannerPluginBase):
            def check(self, url):
                raise Exception("Should not be called")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["http"] = FakeHttpScanner
        plugin_manager.plugins["scanner"]["net"] = FakeNetworkScanner

        plugin_manager.run_other_scans("https://example.com")

        # Should not call check, so no error
        mock_output.error.assert_not_called()
        mock_output.debug.assert_any_call("Running other scanner plugins...")

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_other_scans_handles_plugin_exception(self, mock_output):
        class FailingOtherScanner(plugin_manager.ScannerPluginBase):
            def check(self, url):
                raise ValueError("fail other!")

        plugin_manager.plugins["scanner"].clear()
        plugin_manager.plugins["scanner"]["fail_other"] = FailingOtherScanner

        plugin_manager.run_other_scans("https://example.com")

        # Should call output.error with the exception message
        mock_output.error.assert_any_call(
            mock.ANY  # message includes "Failed to run plugin fail_other: fail other!"
        )
        # Should not call debug for completion for the failing plugin
        calls = [c[0][0] for c in mock_output.debug.call_args_list]
        assert not any(
            "completed successfully" in call for call in calls if "fail_other" in call
        )

    @mock.patch("yawast.scanner.plugins.plugin_manager.output")
    def test_run_other_scans_no_scanner_plugins(self, mock_output):
        plugin_manager.plugins["scanner"].clear()
        plugin_manager.run_other_scans("https://example.com")
        # Should not call output.debug or output.error
        mock_output.debug.assert_not_called()
        mock_output.error.assert_not_called()

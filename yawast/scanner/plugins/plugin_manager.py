#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

# this is the loader for plugins, it will check for installed packages that
# match the naming scheme (yawast_plugin_*) and load them. they are then
# exposed via dictionary, by type and name. for those that derive from
# scanner_plugin_base, they will be called during the scan process.
# for those that derive from hook_scanner_base, they will use the
# defined hooks to acces the scanner and add their own functionality.

import importlib
import sys
from typing import Dict, Type

if sys.version_info < (3, 10):
    from importlib_metadata import entry_points
else:
    from importlib.metadata import entry_points

import pkg_resources

from yawast.scanner.plugins.hook_scanner_base import HookScannerBase
from yawast.scanner.plugins.plugin_base import PluginBase
from yawast.scanner.plugins.scanner_plugin_base import (
    HttpScannerPluginBase,
    NetworkScannerPluginBase,
    ScannerPluginBase,
)
from yawast.shared import output

# Dictionary to hold all loaded plugins
plugins: Dict[str, Dict[str, Type[PluginBase]]] = {"scanner": {}, "hook": {}}


def load_plugins() -> None:
    """
    Load all plugins from installed packages.
    """
    discovered_plugins = entry_points(group="yawast.plugins")
    for entry_point in discovered_plugins:
        try:
            # Load the plugin module
            plugin_module = entry_point.load()
            # Check if the plugin is a subclass of PluginBase
            if issubclass(plugin_module, PluginBase):
                # Add the plugin to the dictionary
                plugin_type = (
                    "scanner"
                    if issubclass(plugin_module, ScannerPluginBase)
                    else "hook"
                )
                plugins[plugin_type][entry_point.name] = plugin_module
                output.debug(f"Loaded plugin: {entry_point.name} ({plugin_type})")
        except Exception as e:
            output.error(f"Failed to load plugin {entry_point.name}: {e}")
            continue


def print_loaded_plugins() -> None:
    """
    Print all loaded plugins.
    """
    plugin_count = sum(len(plugin_dict) for plugin_dict in plugins.values())

    if plugin_count > 0:
        for plugin_type, plugin_dict in plugins.items():
            if len(plugin_dict) == 0:
                continue

            print(f"Loaded {plugin_type} plugins:")
            for plugin_name, plugin_class in plugin_dict.items():
                print(f" - {plugin_name}: {plugin_class.__name__}")

        print()


def run_http_scans(url: str) -> None:
    """
    Run all loaded scanner plugins.
    """
    if "scanner" in plugins and len(plugins["scanner"]) > 0:
        output.debug("Running scanner plugins...")

        for plugin_name, plugin_class in plugins["scanner"].items():
            try:
                # get the plugins that derive from HttpScannerBase
                if issubclass(plugin_class, HttpScannerPluginBase):
                    plugin_instance = plugin_class()
                    plugin_instance.check(url)

                    output.debug(f"Plugin {plugin_name} completed successfully.")
            except Exception as e:
                output.error(f"Failed to run plugin {plugin_name}: {e}")
                continue


def run_network_scans(url: str) -> None:
    """
    Run all loaded network scanner plugins.
    """
    if "scanner" in plugins and len(plugins["scanner"]) > 0:
        output.debug("Running network scanner plugins...")

        for plugin_name, plugin_class in plugins["scanner"].items():
            try:
                # get the plugins that derive from NetworkScannerBase
                if issubclass(plugin_class, NetworkScannerPluginBase):
                    plugin_instance = plugin_class()
                    plugin_instance.check(url)

                    output.debug(f"Plugin {plugin_name} completed successfully.")
            except Exception as e:
                output.error(f"Failed to run plugin {plugin_name}: {e}")
                continue


def run_other_scans(url: str) -> None:
    """
    Run all loaded scanner plugins.
    """
    if "scanner" in plugins and len(plugins["scanner"]) > 0:
        output.debug("Running other scanner plugins...")

        for plugin_name, plugin_class in plugins["scanner"].items():
            try:
                # get the plugins that derive from ScannerPluginBase
                if issubclass(plugin_class, ScannerPluginBase) and not issubclass(
                    plugin_class, (HttpScannerPluginBase, NetworkScannerPluginBase)
                ):
                    plugin_instance = plugin_class()
                    plugin_instance.check(url)

                    output.debug(f"Plugin {plugin_name} completed successfully.")
            except Exception as e:
                output.error(f"Failed to run plugin {plugin_name}: {e}")
                continue

---
layout: default
title: The yawast-ng Plugin System
permalink: /plugins/
---

# yawast-ng Plugin System

yawast-ng supports a flexible plugin system that allows users to extend its scanning capabilities by writing and installing their own plugins. This enables custom checks, integrations, and automation tailored to your needs.

## How Plugins Work

Plugins are Python packages that implement a specific interface and are discovered automatically by yawast-ng at runtime. Plugins must:

- Inherit from one of the base plugin classes (e.g., `ScannerPluginBase`)
- Be installed in the same Python environment as yawast-ng
- Register themselves using Python's `entry_points` mechanism under the `yawast.plugins` group

When yawast-ng starts, it loads all installed plugins and makes them available for use during scans.

## Creating a Plugin

To create your own plugin:

1. **Copy the Sample Plugin**

Use the [sample-plugin](/sample-plugin) directory as a starting point. It contains a minimal, working example.

2. **Inherit from a Plugin Base Class**

Your plugin should inherit from `ScannerPluginBase` (or another appropriate base class) and implement the required methods, such as `check(self, url: str)`.

Example:

```python
from yawast.scanner.plugins.scanner_plugin_base import ScannerPluginBase

class MyPlugin(ScannerPluginBase):
    def __init__(self):
        super().__init__()
        self.name = "MyPlugin"
        self.description = "A custom plugin."
        self.version = "0.1.0"

    def check(self, url: str) -> None:
        # Your scanning logic here
        pass
```

3. **Add an Entry Point**

In your `setup.py`, add an entry point under `yawast.plugins`:

```python
entry_points={
    "yawast.plugins": [
        "my_plugin = my_plugin:MyPlugin",
    ],
},
```

4. **Package and Install**

Build and install your plugin package:

```bash
pip install .
```

yawast-ng will automatically discover and load your plugin the next time it runs.

## Example: Sample Plugin

See the [sample-plugin](https://github.com/Numorian/yawast-ng/tree/main/sample-plugin) directory for a complete, minimal example. This can be copied and modified to create your own plugins.

## Tips

- Use unique names for your plugin and entry point to avoid conflicts.
- Plugins can be distributed as Python packages (e.g., via PyPI or as local packages).
- For advanced use, see the base classes in `yawast/scanner/plugins/` for more plugin types and hooks.

## Troubleshooting

- Ensure your plugin is installed in the same environment as yawast-ng.
- Check the yawast-ng output for plugin loading errors.
- Use the `print_loaded_plugins()` function or equivalent command to verify your plugin is detected.

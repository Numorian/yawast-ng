#  This file is a sample plugin for yawast-ng.
#  Released under the MIT license.

from yawast.scanner.plugins.scanner_plugin_base import HttpScannerPluginBase
from yawast.shared import output


class SamplePlugin(HttpScannerPluginBase):
    """
    A simple example plugin for yawast-ng.
    """

    def __init__(self):
        super().__init__()
        self.name = "SamplePlugin"
        self.description = "A sample plugin that demonstrates the plugin interface."
        self.version = "0.1.0"

    def check(self, url: str) -> None:
        # This is where your plugin logic goes.
        # For demonstration, we'll just print a message (avoid in real plugins).
        output.info(f"SamplePlugin checked: {url}")

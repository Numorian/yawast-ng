#  This file is a sample plugin for yawast-ng.
#  Released under the MIT license.

from requests import Response

from yawast.reporting.enums import Severity, Vulnerabilities
from yawast.scanner.plugins.hook_scanner_base import HookScannerBase
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

        # create a new Vulerability, so that it can be reported
        # after this call, the new vulnerability can be accessed via
        # yawast.reporting.enums.Vulnerabilities.SAMPLE_PLUGIN_FOUND
        # and reported via yawast.reporting.result.Result
        Vulnerabilities.add(
            "SAMPLE_PLUGIN_FOUND",
            Severity.LOW,
            "A sample plugin was found.",
        )

    def check(self, url: str) -> None:
        # This is where your plugin logic goes.
        # For demonstration, we'll just print a message (avoid in real plugins).
        output.info(f"SamplePlugin checked: {url}")


class SampleHookPlugin(HookScannerBase):
    """
    A sample hook plugin for yawast-ng.
    """

    def __init__(self):
        super().__init__()
        self.name = "SampleHookPlugin"
        self.description = "A sample hook plugin that demonstrates the hook interface."
        self.version = "0.1.0"

    def response_received(self, url: str, response: Response) -> None:
        # This is where your hook logic goes.
        # For demonstration, we'll just print a message if the response is large.
        if len(response.content) > 1024 * 100:
            output.info(f"SampleHookPlugin received large response: {url}")

#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from yawast.scanner.plugins.plugin_base import PluginBase


class ScannerPluginBase(PluginBase):
    """
    Base class for all scanner plugins.
    """

    def __init__(self):
        super().__init__()
        self.name = "ScannerPluginBase"
        self.description = "Base class for all scanner plugins."
        self.version = "1.0.0"

    def check(self, url: str) -> None:
        """
        Check the given URL for vulnerabilities.
        """
        raise NotImplementedError("Subclasses must implement this method.")


class HttpScannerPluginBase(ScannerPluginBase):
    """
    Base class for all HTTP scanner plugins.
    """

    def __init__(self):
        super().__init__()
        self.name = "HttpScannerBase"
        self.description = "Base class for all HTTP scanner plugins."
        self.version = "1.0.0"

    def check(self, url: str) -> None:
        """
        Check the given URL for vulnerabilities.
        """
        raise NotImplementedError("Subclasses must implement this method.")


class NetworkScannerPluginBase(ScannerPluginBase):
    """
    Base class for all network scanner plugins.
    """

    def __init__(self):
        super().__init__()
        self.name = "NetworkScannerBase"
        self.description = "Base class for all network scanner plugins."
        self.version = "1.0.0"

    def check(self, url: str) -> None:
        """
        Check the given URL for vulnerabilities.
        """
        raise NotImplementedError("Subclasses must implement this method.")

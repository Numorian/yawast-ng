#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

from requests import Response

from yawast.reporting.injection import InjectionPoint
from yawast.scanner.plugins.plugin_base import PluginBase
from yawast.scanner.session import Session


class HookScannerBase(PluginBase):
    """
    Base class for all hook scanners.
    """

    def __init__(self):
        super().__init__()
        self.name = "HookScannerBase"
        self.description = "Base class for all hook scanners."
        self.version = "1.0.0"

    def response_received(self, url: str, response: Response) -> None:
        """
        Called when a response is received.
        """
        pass

    def injection_point_found(
        self, url: str, point: InjectionPoint, response: Response
    ) -> None:
        """
        Called when an injection point is found.
        :param url: The URL being scanned
        :param point: The injection point found
        :param response: The HTTP response associated with the injection point
        """
        pass

    def scan_complete(self, session: Session) -> None:
        """
        Called when the scan is complete.
        """
        pass

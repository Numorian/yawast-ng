#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from yawast.scanner.plugins.plugin_base import PluginBase


class HookScannerBase(PluginBase):
    """
    Base class for all hook scanners.
    """

    def __init__(self):
        super().__init__()
        self.name = "HookScannerBase"
        self.description = "Base class for all hook scanners."
        self.version = "1.0.0"

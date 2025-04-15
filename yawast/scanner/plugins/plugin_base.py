#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

class PluginBase:
    """
    Base class for all plugins.
    """

    def __init__(self):
        self.name = "PluginBase"
        self.description = "Base class for all plugins."
        self.version = "1.0.0"

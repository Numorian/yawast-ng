#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.


class InjectionPoint:
    """
    Class to represent an injection point in a URL.
    """

    def __init__(self, url: str, field: str, method: str, value: str = ""):
        self.url = url
        self.field = field
        self.method = method
        self.value = value

    def __eq__(self, value):
        return (
            self.url == value.url
            and self.field == value.field
            and self.method == value.method
            and self.value == value.value
        )

    def to_dict(self):
        return {
            "url": self.url,
            "field": self.field,
            "method": self.method,
            "value": self.value,
        }

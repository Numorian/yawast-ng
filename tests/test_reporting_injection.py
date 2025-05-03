import pytest

from yawast.reporting.injection import InjectionPoint


class DummyResponse:
    def __init__(self, text):
        self.text = text
        self.request = None


def test_injection_point_eq():
    a = InjectionPoint("url1", "field1", "GET", "val1")
    b = InjectionPoint("url1", "field1", "GET", "val1")
    c = InjectionPoint("url2", "field1", "GET", "val1")
    assert a == b
    assert not (a == c)


def test_injection_point_to_dict():
    a = InjectionPoint("url1", "field1", "POST", "val2")
    d = a.to_dict()
    assert d == {"url": "url1", "field": "field1", "method": "POST", "value": "val2"}

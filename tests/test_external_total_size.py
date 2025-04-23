from collections import deque

from yawast.external.total_size import total_size


def test_total_size_simple():
    assert total_size(123) > 0
    assert total_size("abc") > 0
    assert total_size([1, 2, 3]) > 0
    assert total_size((1, 2, 3)) > 0
    assert total_size({"a": 1, "b": 2}) > 0
    assert total_size(set([1, 2, 3])) > 0
    assert total_size(frozenset([1, 2, 3])) > 0
    assert total_size(deque([1, 2, 3])) > 0


def test_total_size_nested():
    d = {"a": [1, 2, {"b": (3, 4)}]}
    assert total_size(d) > 0


def test_total_size_custom_handler():
    class Dummy:
        def __init__(self, items):
            self.items = items

        def get_elements(self):
            return self.items

    d = Dummy([1, 2, 3])
    handlers = {Dummy: Dummy.get_elements}
    assert total_size(d, handlers=handlers) > 0


def test_total_size_shared_reference():
    l = [1, 2]
    d = [l, l]
    # Should not double count
    assert total_size(d) > 0

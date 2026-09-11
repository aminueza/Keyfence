import pytest

from calc import add, average, divide, multiply, subtract


def test_add():
    assert add(2, 3) == 5


def test_subtract():
    assert subtract(5, 3) == 2


def test_multiply():
    assert multiply(4, 3) == 12


def test_divide():
    assert divide(9, 3) == 3
    with pytest.raises(ZeroDivisionError):
        divide(1, 0)


def test_average_of_empty_list_is_zero():
    assert average([]) == 0

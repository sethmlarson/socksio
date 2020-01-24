import pytest

from socksio.compat import singledispatchmethod


def test_singledispatchmethod():
    class Foo:
        @singledispatchmethod
        def bar():
            raise NotImplementedError()  # pragma: nocover

        @bar.register(str)
        def _(self, arg: str) -> None:
            return f"<< {arg} >>"

        @bar.register(int)
        def _(self, arg: int) -> None:
            return f"|| {arg} ||"

    obj = Foo()
    assert obj.bar("bar") == "<< bar >>"
    assert obj.bar(1) == "|| 1 ||"


def test_singledispatchmethod_error():
    with pytest.raises(TypeError):
        singledispatchmethod("error")

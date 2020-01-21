"""Backport of @functools.singledispatchmethod to Python <3.7.

Adapted from https://github.com/ikalnytskyi/singledispatchmethod
removing 2.7 specific code.
"""

import functools
import typing


if hasattr(functools, "singledispatchmethod"):
    singledispatchmethod = functools.singledispatchmethod
else:
    update_wrapper = functools.update_wrapper
    singledispatch = functools.singledispatch

    # The type: ignore below is to avoid mypy erroring due to a
    # "already defined" singledispatchmethod, oddly this does not
    # happen when using `if sys.version_info >= (3, 8)`
    class singledispatchmethod(object):  # type: ignore
        """Single-dispatch generic method descriptor."""

        def __init__(self, func: typing.Callable):
            if not callable(func) and not hasattr(func, "__get__"):
                raise TypeError("{!r} is not callable or a descriptor".format(func))

            self.dispatcher = singledispatch(func)
            self.func = func

        def register(
            self,
            cls: typing.Callable,
            method: typing.Callable[[typing.Any], typing.Any],
        ) -> typing.Callable:
            return self.dispatcher.register(cls, func=method)

        def __get__(
            self, obj: typing.Any, cls: typing.Callable[[typing.Any], typing.Any]
        ) -> typing.Callable:
            def _method(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
                method = self.dispatcher.dispatch(args[0].__class__)  # type: typing.Any
                return method.__get__(obj, cls)(*args, **kwargs)

            # The type: ignore below is due to `_method` being given a strict
            # "Callable[[VarArg(Any), KwArg(Any)], Any]" which causes a
            # 'has no attribute "__isabstractmethod__" error'
            # felt safe enough to ignore
            _method.__isabstractmethod__ = self.__isabstractmethod__  # type: ignore
            _method.register = self.register  # type: ignore
            update_wrapper(_method, self.func)
            return _method

        @property
        def __isabstractmethod__(self) -> typing.Any:
            return getattr(self.func, "__isabstractmethod__", False)

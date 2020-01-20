"""Backport of @functools.singledispatchmethod to Python <3.7.

Adapted from https://github.com/ikalnytskyi/singledispatchmethod
removing 2.7 specific code.
"""

import functools
import sys


if sys.version_info >= (3, 8):
    singledispatchmethod = functools.singledispatchmethod
else:
    update_wrapper = functools.update_wrapper
    singledispatch = functools.singledispatch

    # def update_wrapper(
    #     wrapper,
    #     wrapped,
    #     assigned=functools.WRAPPER_ASSIGNMENTS,
    #     updated=functools.WRAPPER_UPDATES,
    # ):
    #     """Backport of Python 3's `functools.update_wrapper`."""

    #     for attr in assigned:
    #         try:
    #             value = getattr(wrapped, attr)
    #         except AttributeError:
    #             pass
    #         else:
    #             setattr(wrapper, attr, value)
    #     for attr in updated:
    #         getattr(wrapper, attr).update(getattr(wrapped, attr, {}))
    #     wrapper.__wrapped__ = wrapped
    #     return wrapper

    # @functools.wraps(singledispatch.singledispatch)
    # def singledispatch(*args, **kwargs):
    #     """Singledispatch that works with @classmethod and @staticmethod."""

    #     try:
    #         rv = singledispatch.singledispatch(*args, **kwargs)
    #     except AttributeError:
    #         # Due to imperfection in Python 2, functools.update_wrapper
    #         # may raise an AttributeError exception when applied to
    #         # @classmethod or @staticmethod. If that happened, the best
    #         # we can do is try one more time using a
    #         # functools.update_wrapper from Python 3 where this issue
    #         # does not exist anymore.
    #         _update_wrapper = singledispatch.update_wrapper
    #         singledispatch.update_wrapper = update_wrapper
    #         rv = singledispatch.singledispatch(*args, **kwargs)
    #         singledispatch.update_wrapper = _update_wrapper
    #     return rv

    class singledispatchmethod(object):
        """Single-dispatch generic method descriptor."""

        def __init__(self, func):
            if not callable(func) and not hasattr(func, "__get__"):
                raise TypeError("{!r} is not callable or a descriptor".format(func))

            self.dispatcher = singledispatch(func)
            self.func = func

        def register(self, cls, method=None):
            return self.dispatcher.register(cls, func=method)

        def __get__(self, obj, cls):
            def _method(*args, **kwargs):
                method = self.dispatcher.dispatch(args[0].__class__)
                return method.__get__(obj, cls)(*args, **kwargs)

            _method.__isabstractmethod__ = self.__isabstractmethod__
            _method.register = self.register
            update_wrapper(_method, self.func)
            return _method

        @property
        def __isabstractmethod__(self):
            return getattr(self.func, "__isabstractmethod__", False)

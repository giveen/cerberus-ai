from __future__ import annotations

from threading import Lock
from typing import Any, Callable, Generic, TypeVar


T = TypeVar("T")


class LazyToolProxy(Generic[T]):
    """Instantiate heavyweight tool singletons only on first real use."""

    def __init__(self, factory: Callable[[], T]) -> None:
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_instance", None)
        object.__setattr__(self, "_lock", Lock())

    def _get_instance(self) -> T:
        instance = object.__getattribute__(self, "_instance")
        if instance is None:
            lock = object.__getattribute__(self, "_lock")
            with lock:
                instance = object.__getattribute__(self, "_instance")
                if instance is None:
                    factory = object.__getattribute__(self, "_factory")
                    instance = factory()
                    object.__setattr__(self, "_instance", instance)
        return instance

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get_instance(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_factory", "_instance", "_lock"}:
            object.__setattr__(self, name, value)
            return
        setattr(self._get_instance(), name, value)

    def __delattr__(self, name: str) -> None:
        if name in {"_factory", "_instance", "_lock"}:
            object.__delattr__(self, name)
            return
        delattr(self._get_instance(), name)

    def __repr__(self) -> str:
        instance = object.__getattribute__(self, "_instance")
        if instance is None:
            factory = object.__getattribute__(self, "_factory")
            factory_name = getattr(factory, "__name__", factory.__class__.__name__)
            return f"LazyToolProxy({factory_name})"
        return repr(instance)

    def __dir__(self) -> list[str]:
        names = set(super().__dir__())
        instance = object.__getattribute__(self, "_instance")
        if instance is not None:
            names.update(dir(instance))
        return sorted(names)
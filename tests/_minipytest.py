"""A ~100-line stand-in for the slice of pytest this suite uses.

This machine's system Python ships without pip or ensurepip, and a forensics
tool that can't run its own tests on the machine it's installed on is not
much of a forensics tool. So: if pytest is present the suite uses it, and if
not it falls back to this.

Implements `mark.parametrize`, `raises`, and a collector/runner. Nothing else.
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, Callable, Iterable


class _Raises:
    def __init__(self, expected):
        self.expected = expected
        self.value: BaseException | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            raise AssertionError(f"DID NOT RAISE {self.expected}")
        if not issubclass(exc_type, self.expected):
            return False
        self.value = exc
        return True


class _Mark:
    @staticmethod
    def parametrize(argnames: str, argvalues: Iterable, ids: list[str] | None = None):
        names = [n.strip() for n in argnames.split(",")]

        def decorator(fn: Callable) -> Callable:
            cases = []
            for i, values in enumerate(argvalues):
                if len(names) == 1:
                    values = (values,)
                label = ids[i] if ids and i < len(ids) else "-".join(
                    str(v)[:20] for v in values)
                cases.append((label, dict(zip(names, values))))
            fn._mini_cases = cases          # type: ignore[attr-defined]
            return fn
        return decorator

    @staticmethod
    def skip(*_a, **_k):
        def decorator(fn):
            fn._mini_skip = True            # type: ignore[attr-defined]
            return fn
        return decorator


class _Pytest:
    mark = _Mark()

    @staticmethod
    def raises(expected):
        return _Raises(expected)

    @staticmethod
    def fail(msg: str = ""):
        raise AssertionError(msg)


pytest = _Pytest()


def run(module: Any) -> int:
    """Run every test_* callable in `module`. Returns a process exit code."""
    passed = failed = 0
    failures: list[tuple[str, str]] = []

    for name in sorted(vars(module)):
        if not name.startswith("test_"):
            continue
        fn = getattr(module, name)
        if not callable(fn) or getattr(fn, "_mini_skip", False):
            continue

        cases = getattr(fn, "_mini_cases", [("", {})])
        for label, kwargs in cases:
            title = f"{name}[{label}]" if label else name
            try:
                fn(**kwargs)
            except Exception:
                failed += 1
                failures.append((title, traceback.format_exc()))
                sys.stdout.write("F")
            else:
                passed += 1
                sys.stdout.write(".")
            sys.stdout.flush()

    print()
    for title, tb in failures:
        print(f"\n{'=' * 70}\nFAIL: {title}\n{'-' * 70}\n{tb}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0

# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
Shared thread-safe LRU cache decorator.

Python's @lru_cache is not fully thread-safe on cache misses before
Python 3.12.  Since scanners run in parallel via ThreadPoolExecutor,
we guard cache access with a lock to prevent data races.
"""

from __future__ import annotations

import threading
from functools import lru_cache, wraps


def threadsafe_lru_cache(maxsize: int = 128):
    """
    Decorator combining @lru_cache with a threading.Lock.

    The wrapper exposes cache_info() and cache_clear() for compatibility
    with existing test fixtures.
    """

    def decorator(fn):
        cached = lru_cache(maxsize=maxsize)(fn)
        lock = threading.Lock()

        @wraps(fn)
        def wrapper(*args, **kwargs):
            with lock:
                return cached(*args, **kwargs)

        wrapper.cache_clear = cached.cache_clear  # type: ignore[attr-defined]
        wrapper.cache_info = cached.cache_info  # type: ignore[attr-defined]
        return wrapper

    return decorator

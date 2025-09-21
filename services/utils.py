import time
from typing import Callable, Any

def timed_call(fn: Callable, *args, **kwargs) -> tuple[Any, float, list[str]]:
    t0 = time.time()
    errors: list[str] = []
    try:
        res = fn(*args, **kwargs)
    except Exception as e:
        res = {"errors": [str(e)]}
    dt = time.time() - t0
    # Merge any inner errors into a top-level list for visibility
    inner_errs = []
    try:
        inner_errs = list(res.get("errors", [])) if isinstance(res, dict) else []
    except Exception:
        inner_errs = []
    return res, dt, inner_errs

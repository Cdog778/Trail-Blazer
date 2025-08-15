from decimal import Decimal

def get_baselined_hours_ns(baseline_item):
    out = set()
    ns = baseline_item.get("work_hours_utc_ns")
    if not ns:
        return out

    if isinstance(ns, set):
        for h in ns:
            out.add(int(h if not isinstance(h, Decimal) else int(h)))
    elif isinstance(ns, list):
        for h in ns:
            out.add(int(h if not isinstance(h, Decimal) else int(h)))
    return out


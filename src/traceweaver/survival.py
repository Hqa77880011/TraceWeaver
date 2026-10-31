"""Discovery-time summaries retaining non-discovery right censoring."""


def kaplan_meier(observations, horizon=None):
    """Return descriptive survival and restricted mean for (duration, discovered)."""
    rows = [(float(t), bool(event)) for t, event in observations]
    if any(t < 0 for t, _ in rows):
        raise ValueError("Observation durations cannot be negative")
    if not rows:
        return {"count": 0, "mean": None, "median": None, "curve": []}
    horizon = max(t for t, _ in rows) if horizon is None else float(horizon)
    at_risk, survival, area, last, median = len(rows), 1.0, 0.0, 0.0, None
    curve = []
    for time in sorted({min(t, horizon) for t, _ in rows}):
        area += survival * (time - last)
        events = sum(t == time and event for t, event in rows) if time <= horizon else 0
        censored = sum(
            t == time and not event or t > horizon and time == horizon
            for t, event in rows
        )
        if events:
            survival *= 1 - events / at_risk
            if median is None and survival <= 0.5:
                median = time
        curve.append(
            dict(
                time=time,
                at_risk=at_risk,
                events=events,
                censored=censored,
                survival=survival,
            )
        )
        at_risk -= events + censored
        last = time
    area += survival * (horizon - last)
    return dict(count=len(rows), mean=area, median=median, horizon=horizon, curve=curve)

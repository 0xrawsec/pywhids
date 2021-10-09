from datetime import datetime

# python datetime is failing at parsing such timestamp that is why we need this function


def parse_rfc3339_nano_timestamp(timestamp: str) -> datetime:
    date, time = timestamp.split("T")
    tz = None
    if len(time.split("-")) == 2:
        time, tz = time.split("-")
        tz = "-" + tz
    elif len(time.split("+")) == 2:
        time, tz = time.split("+")
        tz = "+" + tz
    elif time.endswith("Z"):
        time = time.rstrip("Z")
        tz = "+00:00"
    if tz is None:
        raise ValueError(f"Unexpected timezone: {timestamp}")
    time, nano = time.split(".")
    # in python iso format only goes to 6 digits
    nano = nano[:6]
    # it has to be an even number
    nano += "0" * (6-len(nano))
    return datetime.fromisoformat(f"{date}T{time}.{nano}{tz}")


def removesuffix(s: str, suffix: str, /) -> str:
    # suffix='' should not call self[:-0].
    if suffix and s.endswith(suffix):
        return s[:-len(suffix)]
    else:
        return s

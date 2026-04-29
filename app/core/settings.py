import os


DEFAULT_CORRELATION_WINDOW_HOURS = 24
DEFAULT_MEDIUM_BURST_THRESHOLD = 3
DEFAULT_MEDIUM_BURST_WINDOW_MINUTES = 15
DEFAULT_ATTACK_CHAIN_WINDOW_MINUTES = 10


def get_int_setting(name: str, default: int, minimum: int = 1) -> int:
    raw_value = os.getenv(name, str(default))

    try:
        value = int(raw_value)
    except ValueError:
        return default

    return max(minimum, value)


def get_correlation_window_hours() -> int:
    return get_int_setting(
        "CORRELATION_WINDOW_HOURS",
        DEFAULT_CORRELATION_WINDOW_HOURS,
        minimum=1,
    )


def get_medium_burst_threshold() -> int:
    return get_int_setting(
        "MEDIUM_BURST_THRESHOLD",
        DEFAULT_MEDIUM_BURST_THRESHOLD,
        minimum=2,
    )


def get_medium_burst_window_minutes() -> int:
    return get_int_setting(
        "MEDIUM_BURST_WINDOW_MINUTES",
        DEFAULT_MEDIUM_BURST_WINDOW_MINUTES,
        minimum=1,
    )


def get_attack_chain_window_minutes() -> int:
    return get_int_setting(
        "ATTACK_CHAIN_WINDOW_MINUTES",
        DEFAULT_ATTACK_CHAIN_WINDOW_MINUTES,
        minimum=1,
    )
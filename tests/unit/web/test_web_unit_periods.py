"""Period windows (Today · 7 days · 1 month · 1 year) and their buckets."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from reddysec.web import preferences
from reddysec.web.queries import DAYS_TO_PERIOD, period_window

NOW = datetime(2026, 11, 7, 15, 40, tzinfo=UTC)


def test_today_is_hourly_from_local_midnight():
    p = period_window("today", now=NOW)
    assert p.unit == "hour" and len(p.buckets) == 16
    assert p.since == datetime(2026, 11, 7, tzinfo=UTC) and p.buckets[-1].hour == 15


def test_today_in_a_time_zone():
    la = ZoneInfo("America/Los_Angeles")
    p = period_window("today", now=NOW, tz=la)  # 07:40 in Los Angeles
    assert len(p.buckets) == 8 and p.buckets[0] == datetime(2026, 11, 7, tzinfo=la)
    assert p.since == datetime(2026, 11, 7, 8, tzinfo=UTC)


def test_today_across_a_daylight_saving_change():
    la = ZoneInfo("America/Los_Angeles")
    # 1 Nov 2026: clocks go back at 02:00, so the day has 25 hours.
    p = period_window("today", now=datetime(2026, 11, 2, 7, 30, tzinfo=UTC), tz=la)  # 23:30 local, 1 Nov
    assert len(p.buckets) == 25


@pytest.mark.parametrize(("key", "n"), [("7d", 7), ("1m", 30)])
def test_days(key, n):
    p = period_window(key, now=NOW)
    assert p.unit == "day" and len(p.buckets) == n
    assert p.buckets[-1] == datetime(2026, 11, 7, tzinfo=UTC) and p.since == p.buckets[0]


def test_year_is_twelve_months():
    p = period_window("1y", now=NOW)
    assert p.unit == "month" and len(p.buckets) == 12
    assert p.buckets[0] == datetime(2025, 12, 1, tzinfo=UTC) and p.buckets[-1] == datetime(2026, 11, 1, tzinfo=UTC)
    jan = period_window("1y", now=datetime(2026, 1, 15, tzinfo=UTC))
    assert jan.buckets[0] == datetime(2025, 2, 1, tzinfo=UTC)


def test_unknown_period_is_seven_days():
    assert period_window("forever", now=NOW).key == "7d"


def test_resolve_period():
    assert preferences.resolve_period("1m", "7d") == ("1m", True)
    assert preferences.resolve_period("1m", "1m") == ("1m", False)
    assert preferences.resolve_period(None, "1y") == ("1y", False)
    assert preferences.resolve_period(None, "junk") == ("7d", False)
    assert preferences.resolve_period(None, "7d", days=30) == ("1m", True)
    assert preferences.resolve_period("bogus", "today", days=999) == ("today", False)
    assert DAYS_TO_PERIOD[1] == "today"


@pytest.mark.parametrize(
    ("cookie", "expected"),
    [
        ("Europe/London", ZoneInfo("Europe/London")),
        ("", UTC),
        ("Not/AZone", UTC),
        ("../../etc/passwd", UTC),
        ("/etc/localtime", UTC),
        ("America", UTC),
        ("x" * 80, UTC),
    ],
)
def test_client_tz(cookie, expected):
    request = SimpleNamespace(cookies={preferences.TZ_COOKIE: cookie})
    assert preferences.client_tz(request) == expected

"""Tests for project 75 Login Anomaly Detector."""

from __future__ import annotations

import datetime

from project_75.core import (
    AnomalyDetectorState,
    LoginEvent,
    UserProfile,
    _check_brute_force,
    _check_credential_stuffing,
    _check_impossible_travel,
    _check_new_country,
    _check_new_ip,
    _check_unusual_hour,
    analyse_events,
    parse_log_file,
    parse_login_line,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_TS = datetime.datetime(2024, 6, 15, 10, 0, 0)


def _event(
    status: str = "success",
    username: str = "alice",
    ip: str = "10.0.0.1",
    country: str = "US",
    hour: int = 10,
    offset_hours: float = 0,
) -> LoginEvent:
    ts = _BASE_TS.replace(hour=hour) + datetime.timedelta(hours=offset_hours)
    return LoginEvent(
        timestamp=ts,
        username=username,
        src_ip=ip,
        status=status,
        country=country,
    )


def _profile(
    ips: set[str] | None = None,
    countries: set[str] | None = None,
    typical_hours: set[int] | None = None,
    total_logins: int = 10,
) -> UserProfile:
    p = UserProfile(username="alice")
    p.known_ips = {"10.0.0.1"} if ips is None else ips
    p.known_countries = {"US"} if countries is None else countries
    p.typical_hours = set(range(8, 20)) if typical_hours is None else typical_hours
    p.total_logins = total_logins
    return p


# ---------------------------------------------------------------------------
# parse_login_line
# ---------------------------------------------------------------------------

class TestParseLoginLine:
    def test_success_line(self) -> None:
        e = parse_login_line("2024-01-15T10:30:00 alice 192.168.1.1 success US")
        assert e is not None
        assert e.username == "alice"
        assert e.status == "success"
        assert e.country == "US"

    def test_failure_no_country(self) -> None:
        e = parse_login_line("2024-01-15T10:30:00 bob 10.0.0.5 failure")
        assert e is not None
        assert e.status == "failure"
        assert e.country == ""

    def test_empty_line_none(self) -> None:
        assert parse_login_line("") is None

    def test_comment_none(self) -> None:
        assert parse_login_line("# comment") is None

    def test_invalid_format_none(self) -> None:
        assert parse_login_line("not a valid line at all") is None

    def test_case_insensitive_status(self) -> None:
        e = parse_login_line("2024-01-15T10:30:00 alice 1.2.3.4 SUCCESS")
        assert e is not None
        assert e.status == "success"


# ---------------------------------------------------------------------------
# parse_log_file
# ---------------------------------------------------------------------------

class TestParseLogFile:
    def test_sorted_by_timestamp(self) -> None:
        lines = [
            "2024-01-15T12:00:00 alice 1.2.3.4 success",
            "2024-01-15T10:00:00 alice 1.2.3.4 success",
        ]
        events = parse_log_file(lines)
        assert events[0].timestamp < events[1].timestamp

    def test_invalid_lines_skipped(self) -> None:
        lines = ["bad line", "2024-01-15T10:00:00 alice 1.2.3.4 success"]
        events = parse_log_file(lines)
        assert len(events) == 1


# ---------------------------------------------------------------------------
# _check_brute_force
# ---------------------------------------------------------------------------

class TestCheckBruteForce:
    def test_below_threshold_no_alarm(self) -> None:
        state = AnomalyDetectorState()
        for _ in range(4):
            result = _check_brute_force(_event(status="failure"), state, threshold=5)
        assert result is None

    def test_at_threshold_alarm(self) -> None:
        state = AnomalyDetectorState()
        result = None
        for _ in range(5):
            result = _check_brute_force(_event(status="failure"), state, threshold=5)
        assert result is not None
        assert result.anomaly_type == "BRUTE_FORCE"

    def test_resets_on_success(self) -> None:
        state = AnomalyDetectorState()
        for _ in range(4):
            _check_brute_force(_event(status="failure"), state, threshold=5)
        _check_brute_force(_event(status="success"), state, threshold=5)
        assert state._consecutive_failures["alice"] == 0


# ---------------------------------------------------------------------------
# _check_new_country
# ---------------------------------------------------------------------------

class TestCheckNewCountry:
    def test_new_country_flagged(self) -> None:
        profile = _profile(countries={"US"})
        anomaly = _check_new_country(_event(country="CN"), profile)
        assert anomaly is not None
        assert anomaly.anomaly_type == "NEW_COUNTRY"

    def test_known_country_no_flag(self) -> None:
        profile = _profile(countries={"US"})
        anomaly = _check_new_country(_event(country="US"), profile)
        assert anomaly is None

    def test_no_baseline_no_flag(self) -> None:
        profile = _profile(countries=set())
        anomaly = _check_new_country(_event(country="CN"), profile)
        assert anomaly is None

    def test_failure_not_flagged(self) -> None:
        profile = _profile(countries={"US"})
        anomaly = _check_new_country(_event(status="failure", country="CN"), profile)
        assert anomaly is None


# ---------------------------------------------------------------------------
# _check_new_ip
# ---------------------------------------------------------------------------

class TestCheckNewIP:
    def test_new_ip_flagged(self) -> None:
        profile = _profile(ips={"10.0.0.1"})
        anomaly = _check_new_ip(_event(ip="99.99.99.99"), profile)
        assert anomaly is not None
        assert anomaly.anomaly_type == "NEW_IP"

    def test_known_ip_no_flag(self) -> None:
        profile = _profile(ips={"10.0.0.1"})
        anomaly = _check_new_ip(_event(ip="10.0.0.1"), profile)
        assert anomaly is None


# ---------------------------------------------------------------------------
# _check_unusual_hour
# ---------------------------------------------------------------------------

class TestCheckUnusualHour:
    def test_unusual_hour_flagged(self) -> None:
        profile = _profile(typical_hours=set(range(8, 20)), total_logins=10)
        anomaly = _check_unusual_hour(_event(hour=2), profile)
        assert anomaly is not None
        assert anomaly.anomaly_type == "UNUSUAL_HOUR"

    def test_normal_hour_no_flag(self) -> None:
        profile = _profile(typical_hours={10}, total_logins=10)
        anomaly = _check_unusual_hour(_event(hour=10), profile)
        assert anomaly is None

    def test_no_baseline_no_flag(self) -> None:
        profile = _profile(typical_hours=set(), total_logins=0)
        anomaly = _check_unusual_hour(_event(hour=2), profile)
        assert anomaly is None


# ---------------------------------------------------------------------------
# _check_impossible_travel
# ---------------------------------------------------------------------------

class TestCheckImpossibleTravel:
    def test_rapid_country_change(self) -> None:
        state = AnomalyDetectorState()
        last = _event(country="US", offset_hours=0)
        state._last_success["alice"] = last
        profile = _profile(countries={"US"})
        new_event = _event(country="CN", offset_hours=1)  # 1 hour later
        anomaly = _check_impossible_travel(new_event, profile, state)
        assert anomaly is not None
        assert anomaly.anomaly_type == "IMPOSSIBLE_TRAVEL"

    def test_slow_travel_no_flag(self) -> None:
        state = AnomalyDetectorState()
        last = _event(country="US", offset_hours=0)
        state._last_success["alice"] = last
        profile = _profile(countries={"US"})
        new_event = _event(country="CN", offset_hours=24)  # 24 hours later = fine
        anomaly = _check_impossible_travel(new_event, profile, state)
        assert anomaly is None

    def test_same_country_no_flag(self) -> None:
        state = AnomalyDetectorState()
        last = _event(country="US", offset_hours=0)
        state._last_success["alice"] = last
        profile = _profile(countries={"US"})
        anomaly = _check_impossible_travel(_event(country="US"), profile, state)
        assert anomaly is None


# ---------------------------------------------------------------------------
# _check_credential_stuffing
# ---------------------------------------------------------------------------

class TestCheckCredentialStuffing:
    def test_stuffing_detected(self) -> None:
        events = [
            _event(status="failure", username=f"user{i}", ip="1.2.3.4")
            for i in range(6)
        ]
        anomalies = _check_credential_stuffing(events)
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "CREDENTIAL_STUFFING"

    def test_below_threshold_no_flag(self) -> None:
        events = [
            _event(status="failure", username=f"user{i}", ip="1.2.3.4")
            for i in range(3)
        ]
        assert _check_credential_stuffing(events) == []


# ---------------------------------------------------------------------------
# analyse_events (integration)
# ---------------------------------------------------------------------------

class TestAnalyseEvents:
    def test_empty_no_anomalies(self) -> None:
        state = analyse_events([])
        assert not state.anomalies

    def test_brute_force_detected(self) -> None:
        events = [_event(status="failure")] * 5
        state = analyse_events(events, brute_force_threshold=5)
        assert any(a.anomaly_type == "BRUTE_FORCE" for a in state.anomalies)

    def test_new_country_with_baseline(self) -> None:
        baseline = [_event(status="success", country="US")] * 5
        new_events = [_event(status="success", country="RU")]
        state = analyse_events(new_events, baseline_events=baseline)
        assert any(a.anomaly_type == "NEW_COUNTRY" for a in state.anomalies)

    def test_profile_built_from_baseline(self) -> None:
        baseline = [_event(status="success", country="US", ip="10.0.0.1")] * 3
        state = analyse_events([], baseline_events=baseline)
        profile = state.get_profile("alice")
        assert "US" in profile.known_countries
        assert "10.0.0.1" in profile.known_ips

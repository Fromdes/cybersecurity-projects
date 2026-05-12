"""Tests for project 54 Snort rule generator."""

from __future__ import annotations

from project_54.core import (
    RuleBuilder,
    sql_injection_rule,
    ssh_brute_force_rule,
    validate_rule,
    xss_rule,
)


class TestRuleBuilder:
    def test_basic_build(self) -> None:
        rule = RuleBuilder().msg("Test rule").build()
        assert rule.msg == "Test rule"
        assert rule.action == "alert"
        assert rule.protocol == "tcp"

    def test_content_added(self) -> None:
        rule = RuleBuilder().msg("x").content("SELECT", nocase=True).build()
        assert len(rule.content_options) == 1
        assert rule.content_options[0].nocase is True

    def test_pcre_added(self) -> None:
        rule = RuleBuilder().msg("x").pcre(r"\d+", "i").build()
        assert len(rule.pcre_options) == 1

    def test_threshold_added(self) -> None:
        rule = RuleBuilder().msg("x").threshold("both", 5, 60).build()
        assert rule.threshold_count == 5
        assert rule.threshold_seconds == 60

    def test_sid_unique(self) -> None:
        r1 = RuleBuilder().msg("a").build()
        r2 = RuleBuilder().msg("b").build()
        assert r1.sid != r2.sid


class TestSnortRuleRender:
    def test_render_contains_header(self) -> None:
        rule = (
            RuleBuilder()
            .action("alert")
            .protocol("tcp")
            .src("any", "any")
            .dst("$HTTP_SERVERS", "80")
            .msg("Test alert")
            .build()
        )
        rendered = rule.render()
        assert rendered.startswith("alert tcp any any -> $HTTP_SERVERS 80")

    def test_render_contains_msg(self) -> None:
        rule = RuleBuilder().msg("My detection rule").build()
        assert 'msg:"My detection rule"' in rule.render()

    def test_render_contains_sid(self) -> None:
        rule = RuleBuilder().msg("test").build()
        rendered = rule.render()
        assert f"sid:{rule.sid}" in rendered

    def test_render_content_option(self) -> None:
        rule = RuleBuilder().msg("test").content("evil.exe", nocase=True).build()
        assert 'content:"evil.exe"' in rule.render()
        assert "nocase" in rule.render()

    def test_render_pcre_option(self) -> None:
        rule = RuleBuilder().msg("test").pcre(r"\bSELECT\b", "i").build()
        assert "pcre:" in rule.render()

    def test_render_threshold(self) -> None:
        rule = RuleBuilder().msg("test").threshold("both", 5, 60).build()
        assert "threshold:" in rule.render()


class TestValidateRule:
    def test_valid_rule(self) -> None:
        rule = RuleBuilder().msg("valid").build()
        errors = validate_rule(rule)
        assert errors == []

    def test_invalid_action(self) -> None:
        rule = RuleBuilder().action("unknown").msg("x").build()
        errors = validate_rule(rule)
        assert any(e.field == "action" for e in errors)

    def test_invalid_protocol(self) -> None:
        rule = RuleBuilder().protocol("xyz").msg("x").build()
        errors = validate_rule(rule)
        assert any(e.field == "protocol" for e in errors)

    def test_empty_msg(self) -> None:
        rule = RuleBuilder().msg("").build()
        errors = validate_rule(rule)
        assert any(e.field == "msg" for e in errors)


class TestPresetRules:
    def test_sqli_rule_renders(self) -> None:
        rule = sql_injection_rule()
        rendered = rule.render()
        assert "SQL" in rendered
        assert "SELECT" in rendered

    def test_xss_rule_renders(self) -> None:
        rule = xss_rule()
        assert "XSS" in rule.render()
        assert "<script" in rule.render()

    def test_ssh_brute_force_renders(self) -> None:
        rule = ssh_brute_force_rule()
        assert "SSH" in rule.render()
        assert "threshold:" in rule.render()

    def test_all_presets_valid(self) -> None:
        for fn in (sql_injection_rule, xss_rule, ssh_brute_force_rule):
            rule = fn()
            errors = validate_rule(rule)
            assert errors == [], f"Preset {fn.__name__} has errors: {errors}"

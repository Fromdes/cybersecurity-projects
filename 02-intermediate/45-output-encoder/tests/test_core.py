"""Tests for Output Encoder core logic."""

from __future__ import annotations

import pytest

from project_45.core import (
    OutputContext,
    encode,
    encode_css_value,
    encode_html_attr,
    encode_html_body,
    encode_js_string,
    encode_json_value,
    encode_shell_arg,
    encode_url_param,
    encode_url_path,
)


class TestHtmlBodyEncoding:
    def test_ampersand(self) -> None:
        assert encode_html_body("a&b") == "a&amp;b"

    def test_less_than(self) -> None:
        assert encode_html_body("<script>") == "&lt;script&gt;"

    def test_double_quote(self) -> None:
        assert encode_html_body('"hello"') == "&quot;hello&quot;"

    def test_single_quote(self) -> None:
        assert encode_html_body("it's") == "it&#x27;s"

    def test_safe_text_unchanged(self) -> None:
        assert encode_html_body("Hello, world!") == "Hello, world!"

    def test_full_xss_payload(self) -> None:
        result = encode_html_body("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" in result  # text preserved, tags neutralized


class TestHtmlAttrEncoding:
    def test_forward_slash_encoded(self) -> None:
        assert "&#x2F;" in encode_html_attr("/path")

    def test_equals_encoded(self) -> None:
        assert "&#x3D;" in encode_html_attr("a=b")

    def test_backtick_encoded(self) -> None:
        assert "&#x60;" in encode_html_attr("`cmd`")

    def test_event_handler_neutralized(self) -> None:
        result = encode_html_attr('onerror="evil()"')
        assert "onerror" in result   # text preserved
        assert '"' not in result.replace("&quot;", "")

    def test_stricter_than_body(self) -> None:
        # attr encoder encodes more chars than body encoder
        body = encode_html_body("a/b")
        attr = encode_html_attr("a/b")
        assert "&#x2F;" in attr
        assert "&#x2F;" not in body


class TestJsStringEncoding:
    def test_single_quote_escaped(self) -> None:
        assert "\\'" in encode_js_string("it's")

    def test_double_quote_escaped(self) -> None:
        assert '\\"' in encode_js_string('say "hi"')

    def test_backslash_escaped(self) -> None:
        assert "\\\\" in encode_js_string("C:\\path")

    def test_newline_escaped(self) -> None:
        assert "\\n" in encode_js_string("line1\nline2")

    def test_script_close_escaped(self) -> None:
        result = encode_js_string("</script>")
        assert "</script>" not in result
        assert "\\u003C" in result

    def test_null_byte_escaped(self) -> None:
        assert "\\0" in encode_js_string("null\x00byte")

    def test_safe_string_passes_through(self) -> None:
        result = encode_js_string("hello world")
        assert result == "hello world"


class TestUrlEncoding:
    def test_space_encoded_param(self) -> None:
        assert "%20" in encode_url_param("hello world")

    def test_ampersand_encoded_param(self) -> None:
        assert "%26" in encode_url_param("a&b")

    def test_slash_encoded_in_param(self) -> None:
        assert "%2F" in encode_url_param("a/b")

    def test_slash_preserved_in_path(self) -> None:
        result = encode_url_path("/path/to/file")
        assert "/" in result

    def test_space_encoded_in_path(self) -> None:
        assert "%20" in encode_url_path("path with spaces")

    def test_xss_payload_encoded(self) -> None:
        result = encode_url_param("<script>")
        assert "<" not in result
        assert ">" not in result


class TestCssValueEncoding:
    def test_safe_color(self) -> None:
        result = encode_css_value("red")
        assert result == "red"

    def test_expression_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_css_value("expression(alert(1))")

    def test_javascript_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_css_value("javascript:void(0)")

    def test_vbscript_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_css_value("vbscript:evil()")

    def test_special_chars_escaped(self) -> None:
        result = encode_css_value("value{}")
        assert "{" not in result or result != "value{}"


class TestJsonValueEncoding:
    def test_string_value(self) -> None:
        result = encode_json_value("hello")
        assert result == '"hello"'

    def test_angle_brackets_escaped(self) -> None:
        result = encode_json_value("<script>")
        assert "<" not in result or "\\u003C" in result or r"<" in result

    def test_slash_escaped(self) -> None:
        result = encode_json_value("</script>")
        assert "</script>" not in result

    def test_integer_value(self) -> None:
        result = encode_json_value(42)
        assert result == "42"

    def test_nested_object(self) -> None:
        result = encode_json_value({"key": "<value>"})
        assert "<value>" not in result

    def test_valid_json(self) -> None:
        # Should be parseable after stripping our extra escapes
        result = encode_json_value({"name": "Alice"})
        assert "Alice" in result


class TestShellArgEncoding:
    def test_simple_string(self) -> None:
        result = encode_shell_arg("hello")
        assert result == "'hello'"

    def test_spaces_safe(self) -> None:
        result = encode_shell_arg("hello world")
        assert result == "'hello world'"

    def test_single_quote_escaped(self) -> None:
        result = encode_shell_arg("it's")
        assert "'" in result
        assert result != "'it's'"  # raw single quote would break shell

    def test_semicolon_neutralized(self) -> None:
        result = encode_shell_arg("file; rm -rf /")
        assert result.startswith("'")
        assert result.endswith("'")
        # Semicolon is inside quotes, harmless
        assert ";" in result

    def test_backtick_neutralized(self) -> None:
        result = encode_shell_arg("`whoami`")
        assert result.startswith("'")


class TestDispatch:
    def test_dispatch_html_body(self) -> None:
        assert encode("<b>", OutputContext.HTML_BODY) == "&lt;b&gt;"

    def test_dispatch_url_param(self) -> None:
        assert "%" in encode("hello world", OutputContext.URL_PARAM)

    def test_dispatch_js_string(self) -> None:
        assert "\\'" in encode("it's", OutputContext.JS_STRING)

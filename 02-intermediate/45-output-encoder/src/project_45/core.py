"""Output Encoder — context-aware encoding for safe output in HTML, JS, URL, CSS, JSON.

Defends against: T1059.007 (XSS via reflected/stored output), T1185 (Browser Session
Hijacking via DOM injection), T1565.003 (Stored XSS data manipulation).
"""

from __future__ import annotations

import html
import json
import logging
import re
import urllib.parse
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Context enum
# ---------------------------------------------------------------------------

class OutputContext(str, Enum):
    """Rendering context that determines which encoder to apply."""

    HTML_BODY = "html_body"
    HTML_ATTR = "html_attr"
    JS_STRING = "js_string"
    URL_PARAM = "url_param"
    URL_PATH = "url_path"
    CSS_VALUE = "css_value"
    JSON_VALUE = "json_value"
    SHELL_ARG = "shell_arg"


# ---------------------------------------------------------------------------
# HTML encoding
# ---------------------------------------------------------------------------

_HTML_ATTR_TABLE: dict[int, str] = {
    ord("&"): "&amp;",
    ord("<"): "&lt;",
    ord(">"): "&gt;",
    ord('"'): "&quot;",
    ord("'"): "&#x27;",
    ord("/"): "&#x2F;",
    ord("`"): "&#x60;",
    ord("="): "&#x3D;",
}

_HTML_BODY_TABLE: dict[int, str] = {
    ord("&"): "&amp;",
    ord("<"): "&lt;",
    ord(">"): "&gt;",
    ord('"'): "&quot;",
    ord("'"): "&#x27;",
}


def encode_html_body(value: str) -> str:
    """Encode a string for safe insertion into HTML text content.

    Encodes &, <, >, ", ' to prevent tag injection.

    Args:
        value: Untrusted string to encode.

    Returns:
        HTML-safe string for text nodes.
    """
    return value.translate(_HTML_BODY_TABLE)


def encode_html_attr(value: str) -> str:
    """Encode a string for safe insertion into an HTML attribute value.

    More aggressive than HTML body — also encodes /, `, = to block
    attribute injection and event handler patterns.

    Args:
        value: Untrusted string to encode.

    Returns:
        HTML-safe string for quoted attribute values.
    """
    return value.translate(_HTML_ATTR_TABLE)


# ---------------------------------------------------------------------------
# JavaScript encoding
# ---------------------------------------------------------------------------

_JS_ESCAPE_TABLE: dict[int, str] = {
    ord("\\"): "\\\\",
    ord("'"): "\\'",
    ord('"'): '\\"',
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
    ord("\x00"): "\\0",
    ord("<"): "\\u003C",   # </script> escape
    ord(">"): "\\u003E",
    ord("&"): "\\u0026",
    ord("="): "\\u003D",
    ord("`"): "\\u0060",
}


def encode_js_string(value: str) -> str:
    """Encode a string for safe embedding inside a JavaScript string literal.

    Escapes backslash, quotes, newlines, and characters that could break out
    of a `<script>` block.

    Args:
        value: Untrusted string to encode.

    Returns:
        JS-safe string (without surrounding quotes).
    """
    result = value.translate(_JS_ESCAPE_TABLE)
    # Encode any remaining non-ASCII or control characters
    def _escape_char(c: str) -> str:
        n = ord(c)
        if n > 127 or n < 32:  # noqa: PLR2004
            return f"\\u{n:04X}"
        return c

    return "".join(_escape_char(c) if c not in _JS_ESCAPE_TABLE.values() and (ord(c) > 127 or ord(c) < 32) else c for c in result)


# ---------------------------------------------------------------------------
# URL encoding
# ---------------------------------------------------------------------------

def encode_url_param(value: str) -> str:
    """Percent-encode a string for use as a URL query parameter value.

    Args:
        value: Untrusted string.

    Returns:
        Percent-encoded string safe for query parameters.
    """
    return urllib.parse.quote(value, safe="")


def encode_url_path(value: str) -> str:
    """Percent-encode a path segment (preserves / separators).

    Args:
        value: URL path string.

    Returns:
        Encoded path (/ is preserved; other special chars encoded).
    """
    return urllib.parse.quote(value, safe="/")


# ---------------------------------------------------------------------------
# CSS encoding
# ---------------------------------------------------------------------------

_CSS_UNSAFE: re.Pattern[str] = re.compile(r"[^\w\s\-.,#%():/]")


def encode_css_value(value: str) -> str:
    """Encode a string for safe use as a CSS property value.

    Escapes non-word, non-whitespace, non-CSS-safe characters as CSS
    unicode escapes (\\HH).

    Args:
        value: Untrusted string to encode.

    Returns:
        CSS-safe string.

    Raises:
        ValueError: If the value contains a CSS expression() call.
    """
    lower = value.lower()
    if "expression(" in lower or "javascript:" in lower or "vbscript:" in lower:
        raise ValueError(f"Dangerous CSS value rejected: {value!r}")

    def _css_escape(m: re.Match[str]) -> str:
        return f"\\{ord(m.group()):X} "

    return _CSS_UNSAFE.sub(_css_escape, value)


# ---------------------------------------------------------------------------
# JSON encoding
# ---------------------------------------------------------------------------

def encode_json_value(value: Any) -> str:
    """Serialize a value to a JSON string with XSS-safe escaping.

    The standard `json.dumps` does not escape `/` or angle brackets,
    which can lead to `</script>` injection in inline JSON.
    This function applies additional escaping.

    Args:
        value: Any JSON-serializable Python value.

    Returns:
        JSON string with `<`, `>`, `/` escaped as Unicode sequences.
    """
    raw = json.dumps(value, ensure_ascii=False)
    # Escape characters that could break out of <script> blocks
    raw = raw.replace("<", r"\u003C")
    raw = raw.replace(">", r"\u003E")
    raw = raw.replace("/", r"\u002F")
    raw = raw.replace(" ", "\u2028")  # Line separator
    raw = raw.replace(" ", "\u2029")  # Paragraph separator
    return raw


# ---------------------------------------------------------------------------
# Shell argument encoding
# ---------------------------------------------------------------------------

def encode_shell_arg(value: str) -> str:
    """Quote a string for safe use as a shell argument (single-quote wrapping).

    The safest way to pass untrusted data to shell commands. Single-quote
    wrapping prevents all shell metacharacter interpretation except embedded
    single quotes, which are handled by splitting the quoting.

    Args:
        value: Untrusted string to pass as shell argument.

    Returns:
        Shell-safe single-quoted string including surrounding quotes.

    Note:
        Prefer subprocess with a list of arguments over shell=True. This
        function is provided for cases where shell strings are unavoidable.
    """
    # Replace each ' with '"'"' (end quote, literal quote, reopen quote)
    escaped = value.replace("'", "'\"'\"'")
    return f"'{escaped}'"


# ---------------------------------------------------------------------------
# Auto-encoder dispatcher
# ---------------------------------------------------------------------------

def encode(value: str, context: OutputContext) -> str:
    """Dispatch to the correct encoder for the given output context.

    Args:
        value: Untrusted string to encode.
        context: Target rendering context.

    Returns:
        Encoded string.

    Raises:
        ValueError: For CSS values with dangerous constructs.
        NotImplementedError: For unrecognised contexts.
    """
    dispatch = {
        OutputContext.HTML_BODY: encode_html_body,
        OutputContext.HTML_ATTR: encode_html_attr,
        OutputContext.JS_STRING: encode_js_string,
        OutputContext.URL_PARAM: encode_url_param,
        OutputContext.URL_PATH: encode_url_path,
        OutputContext.CSS_VALUE: encode_css_value,
        OutputContext.JSON_VALUE: encode_json_value,
        OutputContext.SHELL_ARG: encode_shell_arg,
    }
    fn = dispatch.get(context)
    if fn is None:
        raise NotImplementedError(f"No encoder for context: {context}")
    result = fn(value)
    logger.debug("Encoded context=%s input_len=%d output_len=%d", context.value, len(value), len(result))
    return result

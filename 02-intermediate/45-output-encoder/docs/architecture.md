# Architecture — Output Encoder

## Components

```
core.py   8 encoder functions + encode() dispatcher + OutputContext enum
cli.py    Click CLI (encode / demo / compare)
```

## Encoder Map

| Context | Function | Key escapes |
|---------|----------|-------------|
| `html_body` | `encode_html_body()` | `& < > " '` |
| `html_attr` | `encode_html_attr()` | `& < > " ' / = \`` |
| `js_string` | `encode_js_string()` | `\ ' " \n \r \t \x00 < > &` |
| `url_param` | `encode_url_param()` | All non-unreserved chars (`safe=""`) |
| `url_path` | `encode_url_path()` | All except `/` |
| `css_value` | `encode_css_value()` | Non-`[\\w\\s\\-.,#%():/]`; rejects `expression()` |
| `json_value` | `encode_json_value()` | `< > /` (inline-script safe) |
| `shell_arg` | `encode_shell_arg()` | Single-quote wrapping; `'` → `'"'"'` |

## Why Context Matters

Using the wrong encoder for the context leads to XSS:
- `encode_html_body()` on a JS string: `alert('xss')` → alert survives
- `encode_url_param()` on HTML: `%3Cscript%3E` renders as `<script>` when URL-decoded

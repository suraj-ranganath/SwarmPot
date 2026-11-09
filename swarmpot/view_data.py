"""Shared read-only JSON and credential redaction helpers for operator views."""
import json
import os
import re


def redact(value):
    if isinstance(value, dict):
        return {k: '[omitted: private model reasoning]' if k.lower() in ('reasoning', 'reasoning_content', 'hidden_reasoning', 'chain_of_thought') else '[redacted]' if re.search(r'password|secret|api_key|authorization|credential|access_token|private_key', k, re.I)
                else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(('{', '[')):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (dict, list)):
                return json.dumps(redact(parsed))
        except (ValueError, RecursionError):
            pass
    for key, secret in os.environ.items():
        if re.search(r'KEY|TOKEN|PASSWORD|SECRET', key) and len(secret) >= 8:
            value = value.replace(secret, '[redacted]')
    value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----', '[redacted private key]', value)
    value = re.sub(r'(?i)((?:bearer|basic)\s+)[\w.\-/+=]+', r'\1[redacted]', value)
    value = re.sub(r'(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token|credential)[\w-]*[\s\"\x27]*[:=][\s\"\x27]*)[^\s,;\"\x27}]+',
                   r'\1[redacted]', value)
    value = re.sub(r'(?i)(https?://)[^\s/@:]+:[^\s/@]+@', r'\1[redacted]@', value)
    return re.sub(r'\bsk-[A-Za-z0-9_-]{12,}', '[redacted]', value)


def read_object(path):
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}

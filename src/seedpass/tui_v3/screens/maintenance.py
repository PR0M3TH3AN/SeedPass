from __future__ import annotations


MAINTENANCE_CSS = """
.maintenance-title {
    background: #000000;
    color: #ffffff;
    text-style: bold;
    text-align: center;
    height: 3;
    border: solid #333333;
    padding: 0 1;
    margin: 1 2;
}

.maintenance-footer {
    background: #111111;
    color: #aaaaaa;
    text-align: center;
    height: 3;
    border: solid #333333;
    padding: 0 1;
    margin: 0 2 1 2;
}

.maintenance-panel-dark {
    padding: 1 2;
    border: heavy #444444;
    background: #000000;
    margin: 0 2 1 2;
}

.maintenance-panel-light {
    padding: 1 2;
    border: heavy #444444;
    background: #f3f3f3;
    margin: 0 2 1 2;
}

.maintenance-intro-dark {
    color: #d7d7d7;
    background: #111111;
    border: round #555555;
    padding: 1;
    margin-bottom: 1;
}

.maintenance-intro-light {
    color: #222222;
    background: #e6e6e6;
    border: round #555555;
    padding: 1;
    margin-bottom: 1;
}

.maintenance-status-dark {
    color: #ffffff;
    background: #111111;
    border: solid #444444;
    padding: 1;
    margin-top: 1;
    min-height: 3;
}

.maintenance-status-light {
    color: #000000;
    background: #e6e6e6;
    border: solid #444444;
    padding: 1;
    margin-top: 1;
    min-height: 3;
}

.maintenance-status-warning {
    background: #4a3800;
    color: #ffdd88;
    border: solid #aa7700;
    padding: 1;
    margin-top: 1;
    min-height: 3;
}

.maintenance-label {
    color: #ffffff;
    text-style: bold;
    margin-top: 1;
    margin-bottom: 0;
}

.maintenance-input {
    background: #ffffff;
    color: #000000;
    border: tall #222222;
    margin-bottom: 1;
}

.maintenance-actions {
    height: 3;
    margin-top: 2;
    content-align: right middle;
}

.maintenance-actions Button {
    margin-left: 1;
    text-style: bold;
}

.maintenance-primary {
    background: #ffffff;
    color: #000000;
    border: solid black;
}

.maintenance-danger {
    background: #880000;
    color: #ffffff;
    border: solid #ff4444;
}

.maintenance-secondary {
    background: #222222;
    color: #ffffff;
    border: solid #888888;
}
"""


_STATUS_ICONS: dict[str, str] = {
    "ready": "◎",
    "working": "⟳",
    "success": "✓",
    "warning": "⚠",
    "error": "✗",
    "danger": "⚠",
    "info": "ℹ",
}


def format_status(level: str, message: str) -> str:
    key = level.strip().lower()
    icon = _STATUS_ICONS.get(key, "◉")
    prefix = key.capitalize() or "Info"
    return f"{icon} {prefix}: {message}"

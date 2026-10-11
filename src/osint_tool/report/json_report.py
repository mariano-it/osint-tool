from __future__ import annotations

import json

from osint_tool.models import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"

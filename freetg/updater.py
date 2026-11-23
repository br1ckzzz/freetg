"""Anonymous GitHub Releases update checker for FreeTG."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from . import __version__

log = logging.getLogger("freetg.updater")

GITHUB_REPO = "br1ckzzz/freetg"
LATEST_RELEASE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
RELEASES_PAGE_URL = f"https://github.com/{GITHUB_REPO}/releases"

_VER_RE = re.compile(r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$", re.IGNORECASE)


@dataclass(frozen=True)
class UpdateInfo:
    tag: str
    version: str
    html_url: str
    download_url: str
    notes_summary: str
    published_at: str


def parse_version(raw: str) -> Tuple[int, int, int, int]:
    """Parse version string into (major, minor, patch, is_stable) for comparison."""
    s = (raw or "").strip()
    if not s:
        return (0, 0, 0, 0)
    m = _VER_RE.match(s)
    if not m:
        return (0, 0, 0, 0)
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    tail = (m.group(4) or "").strip()
    is_stable = 0 if tail else 1
    return (major, minor, patch, is_stable)


def is_newer_version(latest_tag: str, current_version: str = __version__) -> bool:
    """Return True if latest_tag strictly supersedes current_version."""
    latest = parse_version(latest_tag)
    if latest == (0, 0, 0, 0):
        return False
    return latest > parse_version(current_version)


def _summarize_notes(body: str, *, max_lines: int = 6, max_chars: int = 420) -> str:
    lines = []
    for raw_line in (body or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("### Проверка целостности"):
            if line.startswith("### Проверка целостности"):
                break
            continue
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = line.replace("**", "").replace("`", "")
        lines.append(line)
        if len(lines) >= max_lines:
            break
    summary = "\n".join(lines)
    if len(summary) > max_chars:
        summary = summary[: max_chars - 1].rstrip() + "…"
    return summary or "Доступен новый релиз на GitHub."


def parse_release_payload(
    data: Any, current_version: str = __version__
) -> Optional[UpdateInfo]:
    """Parse a GitHub Release JSON dict and return UpdateInfo if newer than current_version."""
    if not isinstance(data, dict) or data.get("draft"):
        return None
    tag = str(data.get("tag_name") or data.get("name") or "").strip()
    if not tag or not is_newer_version(tag, current_version):
        return None

    html_url = str(data.get("html_url") or RELEASES_PAGE_URL).strip()
    download_url = html_url
    assets = data.get("assets")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = str(asset.get("name") or "").strip().lower()
            url = str(asset.get("browser_download_url") or "").strip()
            if url and (name == "freetg.exe" or name.endswith(".exe")):
                download_url = url
                if name == "freetg.exe":
                    break

    clean_ver = tag.lstrip("vV").strip()
    return UpdateInfo(
        tag=tag,
        version=clean_ver,
        html_url=html_url,
        download_url=download_url,
        notes_summary=_summarize_notes(str(data.get("body") or "")),
        published_at=str(data.get("published_at") or "").strip(),
    )


def check_for_update_sync(
    current_version: str = __version__,
    *,
    timeout: float = 6.0,
) -> Tuple[Optional[UpdateInfo], Optional[str]]:
    """Query GitHub latest release anonymously; returns (UpdateInfo | None, error | None)."""
    req = urllib.request.Request(
        LATEST_RELEASE_API_URL,
        headers={
            "User-Agent": f"FreeTG/{current_version}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        return parse_release_payload(payload, current_version=current_version), None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        return None, f"GitHub HTTP {exc.code}"
    except Exception as exc:
        log.debug("Update check failed: %r", exc)
        return None, str(exc)

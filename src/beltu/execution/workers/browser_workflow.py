from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from beltu.policy.scope_guard import ScopeGuard
from beltu.execution.workers.common import bounded_int, redact_url, scope_url

BROWSER_ROOT = Path.cwd() / "data" / "runtime" / "browser"
SESSION_ROOT = Path.cwd() / "data" / "runtime" / "sessions"


def _safe_name(name: str) -> Path:
    value = str(name).strip()
    if not value or "/" in value or "\\\\" in value or ".." in value:
        raise ValueError("browser output name must be a simple local name")
    root = SESSION_ROOT.resolve()
    path = (root / (value if value.endswith(".json") else value + ".json")).resolve()
    if path.parent != root:
        raise ValueError("browser session path escaped runtime session directory")
    return path


def emit(kind: str, subject: str, data: dict[str, Any], confidence: float = 0.84) -> None:
    print(json.dumps({
        "kind": kind, "subject": subject, "data": data,
        "source": "beltu-browser-worker", "confidence": confidence,
    }, ensure_ascii=False))


async def run(job: dict[str, Any]) -> None:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Browser capability requires Playwright. Install BELTU with: pip install -e '.[browser]' and run playwright install chromium") from exc

    target = str(job.get("target", "")).strip()
    scope = ScopeGuard(Path.cwd() / "config" / "scope.yaml")
    steps = job.get("steps") or []
    if not isinstance(steps, list) or not steps:
        raise ValueError("browser automation requires a non-empty steps list")
    max_steps = bounded_int(job.get("max_steps"), default=30, minimum=1, maximum=40, name="max_steps")
    if len(steps) > max_steps:
        raise ValueError(f"browser steps exceed BELTU limit of {max_steps}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=bool(job.get("headless", True)))
        storage_state = None
        if job.get("session_profile"):
            profile = _safe_name(str(job["session_profile"]))
            if profile.exists():
                storage_state = str(profile)
        context = await browser.new_context(storage_state=storage_state)

        async def route_handler(route):
            try:
                scope_url(scope, route.request.url)
                await route.continue_()
            except Exception:
                await route.abort()

        await context.route("**/*", route_handler)
        page = await context.new_page()
        network_count = 0

        async def on_response(response):
            nonlocal network_count
            if network_count >= 100:
                return
            network_count += 1
            try:
                safe = scope_url(scope, response.url)
            except Exception:
                return
            emit("browser.response", redact_url(safe), {
                "status": response.status,
                "resource_type": response.request.resource_type,
                "method": response.request.method,
            }, 0.78)

        page.on("response", on_response)

        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                raise ValueError(f"browser step #{index} must be an object")
            action = str(step.get("action", "")).strip().lower()
            if action == "goto":
                url = scope_url(scope, str(step.get("url", "")))
                await page.goto(url, wait_until="domcontentloaded", timeout=min(int(step.get("timeout_ms", 30000)), 60000))
                emit("browser.navigation", redact_url(page.url), {"step": index, "title": await page.title()})
            elif action == "click":
                await page.locator(str(step["selector"])).first.click(timeout=30000)
                emit("browser.action", redact_url(page.url), {"step": index, "action": "click"})
            elif action == "fill":
                await page.locator(str(step["selector"])).first.fill(str(step.get("value", "")), timeout=30000)
                emit("browser.action", page.url, {"step": index, "action": "fill", "field": str(step["selector"])})
            elif action == "press":
                await page.locator(str(step["selector"])).first.press(str(step.get("key", "Enter")), timeout=30000)
                emit("browser.action", page.url, {"step": index, "action": "press", "field": str(step["selector"])})
            elif action == "wait_for":
                await page.locator(str(step["selector"])).first.wait_for(state=str(step.get("state", "visible")), timeout=30000)
                emit("browser.action", page.url, {"step": index, "action": "wait_for", "field": str(step["selector"])})
            elif action == "extract_text":
                value = await page.locator(str(step["selector"])).first.inner_text(timeout=30000)
                emit("browser.extraction", redact_url(page.url), {"step": index, "selector": str(step["selector"]), "text_length": len(value), "text_sample": value[:2000]})
            elif action == "screenshot":
                BROWSER_ROOT.mkdir(parents=True, exist_ok=True)
                name = str(step.get("name", f"step-{index}.png"))
                if "/" in name or "\\\\" in name or ".." in name:
                    raise ValueError("screenshot name must stay inside the browser runtime directory")
                path = (BROWSER_ROOT / name).resolve()
                if path.parent != BROWSER_ROOT.resolve():
                    raise ValueError("screenshot path escaped browser runtime directory")
                await page.screenshot(path=str(path), full_page=bool(step.get("full_page", False)))
                emit("browser.evidence", redact_url(page.url), {"step": index, "path": str(path.relative_to(Path.cwd()))})
            else:
                raise ValueError(f"Unsupported browser action: {action}")

        save_name = job.get("save_session")
        if save_name:
            path = _safe_name(str(save_name))
            path.parent.mkdir(parents=True, exist_ok=True)
            await context.storage_state(path=str(path))
            try:
                path.chmod(0o600)
            except OSError:
                pass
            emit("session.saved", target, {"profile": path.name})
        emit("browser.summary", target, {"steps": len(steps), "network_events": network_count})
        await context.close()
        await browser.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-file", required=True)
    args = parser.parse_args()
    job = json.loads(Path(args.job_file).read_text(encoding="utf-8"))
    if not isinstance(job, dict):
        raise ValueError("browser job must be a JSON object")
    asyncio.run(run(job))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

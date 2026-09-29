"""Regenerate the README screenshots (docs/images/*.png) from the demo case.

Runs `netforensic demo` into a throwaway cases directory, serves the web UI on
it, and captures each page with headless Chrome/Chromium/Edge using a
throwaway profile (your real browser profile is never touched). Pillow, if
installed, reduces each PNG to a 256-colour palette - the dark UI loses
nothing visible and the files shrink by about 60%.

    python samples/capture_screenshots.py [--browser PATH]

Needs the [pcap,web] extras. Everything shown is the fabricated demo incident.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

PAGES = {
    "story": "#/case/INC-0001/story",
    "overview": "#/case/INC-0001",
    "detections": "#/case/INC-0001/detections",
    "timeline": "#/case/INC-0001/timeline",
}
PORT = 8767
OUT = Path(__file__).resolve().parent.parent / "docs" / "images"

_CANDIDATES = (
    "chrome",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "msedge",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def _find_browser(explicit):
    for candidate in ([explicit] if explicit else []) + list(_CANDIDATES):
        found = shutil.which(candidate) or (candidate if Path(candidate).exists() else None)
        if found:
            return found
    raise SystemExit("No Chrome/Chromium/Edge found; pass --browser PATH.")


def _wait_for(url, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except OSError:
            time.sleep(0.3)
    raise SystemExit(f"The web UI did not come up at {url}")


def _shrink(path):
    try:
        from PIL import Image
    except ImportError:
        return
    image = Image.open(path).convert("RGB")
    image.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(path, optimize=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--browser", help="path to a Chrome/Chromium/Edge executable")
    args = parser.parse_args()
    browser = _find_browser(args.browser)
    OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as scratch:
        cases = Path(scratch) / "cases"
        cli = [sys.executable, "-m", "netforensicai.cli"]
        subprocess.run([*cli, "demo", "--cases-dir", str(cases)], check=True, capture_output=True)
        server = subprocess.Popen([*cli, "web", "--cases-dir", str(cases), "--port", str(PORT)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            base = f"http://127.0.0.1:{PORT}/"
            _wait_for(base)
            for name, route in PAGES.items():
                target = OUT / f"{name}.png"
                subprocess.run(
                    [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars",
                     f"--user-data-dir={Path(scratch) / 'profile'}", "--window-size=1440,900",
                     "--force-device-scale-factor=1", "--virtual-time-budget=8000",
                     f"--screenshot={target}", base + route],
                    check=True, capture_output=True, timeout=120,
                )
                _shrink(target)
                print(f"{target} ({target.stat().st_size // 1024} KB)")
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()

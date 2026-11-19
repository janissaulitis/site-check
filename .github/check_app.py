"""Opens the live app in a real browser. Mode "wake": just make sure it is awake.
Mode "test": also run a real check of the portfolio site and look for errors, with screenshots (laptop light, phone dark)."""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

URL = "https://site-check.streamlit.app/"
SITE = "janis-saulitis-portfolio.netlify.app"
mode = sys.argv[1] if len(sys.argv) > 1 else "wake"
out = Path("out"); out.mkdir(exist_ok=True)


def open_app(page):
    page.goto(URL, timeout=120_000)
    page.wait_for_timeout(8_000)
    wake = page.get_by_role("button", name="Yes, get this app back up!")
    if wake.count():
        print("was asleep, waking up"); wake.click(); page.wait_for_timeout(90_000)
    app = page.frame_locator("iframe[title='streamlitApp']")
    app.locator(".k-name").first.wait_for(timeout=180_000)
    return app


with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={"width": 1366, "height": 900}, color_scheme="light")
    app = open_app(page)
    print("awake:", app.locator(".k-name").first.inner_text())
    if mode == "test":
        app.locator(".st-key-k_bar input").fill(SITE)
        app.locator(".st-key-k_bar input").press("Enter")
        app.get_by_text(f"{SITE} · checked").first.wait_for(timeout=120_000)
        page.wait_for_timeout(40_000)  # Mozilla's second opinion
        page.screenshot(path=str(out / "1_laptop_light.png"), full_page=True)
        (out / "1_page.txt").write_text(app.locator("[data-testid=stMain]").inner_text())
        bad = app.locator("[data-testid=stException]")
        phone = b.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2, color_scheme="dark")
        open_app(phone); phone.wait_for_timeout(6_000)
        phone.screenshot(path=str(out / "2_phone_dark.png"), full_page=True)
        if bad.count():
            print("FAILED:", bad.first.inner_text()[:800]); sys.exit(1)
        print("test finished, no errors")
    b.close()

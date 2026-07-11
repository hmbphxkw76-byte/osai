"""
Human-like behavior simulation utilities.
Provides realistic mouse movement, typing, scrolling, and delay patterns
to evade bot detection based on behavioral analysis.

Inspired by open-source projects:
- ghost-cursor (bezier-curve mouse movement)
- playwright-stealth (stealth patches)
- human_curl (TLS fingerprint humanization)
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

from rich.console import Console

console = Console()


class HumanBehavior:
    """Human-like browser interaction patterns.

    All timing defaults are calibrated against real user data distributions:
    - Reading time: exponential distribution, mean ~300ms per element
    - Mouse movement: Fitt's law + random jitter
    - Typing speed: normal distribution ~40-60 WPM with occasional pauses
    - Scroll behavior: chunked with random pauses
    """

    # ── Timing distributions ──

    @staticmethod
    def think_delay(min_ms: float = 200, max_ms: float = 1500) -> float:
        """Random think-time delay, exponentially weighted toward faster.
        Returns seconds to await.
        """
        return min(max(random.expovariate(1 / 0.3), min_ms / 1000), max_ms / 1000)

    @staticmethod
    def typing_delay() -> float:
        """Typing delay between keystrokes (seconds).
        Realistic: 150-400ms for most characters, slower for punctuation.
        """
        return random.uniform(0.05, 0.15)

    @staticmethod
    def pause_delay() -> float:
        """Occasional pause during typing (seconds).
        5% probability of a "thinking" pause.
        """
        return random.uniform(0.4, 1.8)

    @staticmethod
    def scroll_delay() -> float:
        """Delay between scroll chunks (seconds)."""
        return random.uniform(0.8, 3.0)

    # ── Mouse movement ──

    @staticmethod
    async def human_click(page, target_x: float, target_y: float):
        """Move mouse to target with bezier curve, then click.
        Uses Fitt's law for timing and adds micro-jitter.

        Args:
            page: Playwright Page
            target_x, target_y: Target coordinates
        """
        # Get current mouse position
        viewport = page.viewport_size or {"width": 1440, "height": 900}
        start_x = random.randint(50, viewport["width"] - 100)
        start_y = random.randint(80, viewport["height"] - 100)

        # Bezier control points with randomness
        cp1_x = start_x + (target_x - start_x) * random.uniform(0.2, 0.5)
        cp1_y = start_y + (target_y - start_y) * random.uniform(-0.2, 0.2)
        cp2_x = start_x + (target_x - start_x) * random.uniform(0.5, 0.8)
        cp2_y = start_y + (target_y - start_y) * random.uniform(-0.2, 0.2)

        # Calculate distance for Fitt's law timing
        distance = ((target_x - start_x) ** 2 + (target_y - start_y) ** 2) ** 0.5
        duration = max(0.2, min(0.8, distance / 1000 + 0.2))

        steps = random.randint(20, 40)
        for i in range(steps + 1):
            t = i / steps
            # Cubic bezier
            x = (
                (1 - t) ** 3 * start_x
                + 3 * (1 - t) ** 2 * t * cp1_x
                + 3 * (1 - t) * t ** 2 * cp2_x
                + t ** 3 * target_x
            )
            y = (
                (1 - t) ** 3 * start_y
                + 3 * (1 - t) ** 2 * t * cp1_y
                + 3 * (1 - t) * t ** 2 * cp2_y
                + t ** 3 * target_y
            )
            # Micro-jitter
            x += random.uniform(-1.5, 1.5)
            y += random.uniform(-1.5, 1.5)

            await page.mouse.move(x, y)
            await asyncio.sleep(duration / steps * random.uniform(0.8, 1.2))

        # Slight pause before click
        await asyncio.sleep(random.uniform(0.05, 0.15))
        await page.mouse.click(target_x, target_y)

    @staticmethod
    async def human_click_element(page, element) -> bool:
        """Click an element with human-like mouse movement.

        Returns True if successful, False if element not found.
        """
        try:
            box = await element.bounding_box()
            if not box:
                return False
            # Click near center but with slight offset
            target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
            target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
            await HumanBehavior.human_click(page, target_x, target_y)
            return True
        except Exception:
            # Fallback: direct click
            try:
                await element.click()
                return True
            except Exception:
                return False

    # ── Keyboard typing ──

    @staticmethod
    async def human_type(page, text: str, pauses: bool = True):
        """Type text character by character with realistic timing.

        Args:
            page: Playwright Page
            text: Text to type
            pauses: Whether to simulate "thinking" pauses (5% per char)
        """
        for i, char in enumerate(text):
            await page.keyboard.type(char, delay=random.randint(30, 120))
            # Occasional pause (every ~20 chars or 5% probability)
            if pauses and (random.random() < 0.05 or (i > 0 and i % 20 == 0)):
                await asyncio.sleep(HumanBehavior.pause_delay())

    # ── Scrolling ──

    @staticmethod
    async def human_scroll(page, direction: str = "down", distance: Optional[int] = None):
        """Scroll like a human: chunked, with random pauses between chunks.

        Args:
            page: Playwright Page
            direction: "up" or "down"
            distance: Pixels to scroll. Auto-calculated if None.
        """
        if distance is None:
            distance = random.randint(200, 600)

        sign = 1 if direction == "down" else -1
        chunk_count = random.randint(2, 4)
        chunk_size = distance / chunk_count

        for _ in range(chunk_count):
            jittered = chunk_size * random.uniform(0.8, 1.2)
            await page.mouse.wheel(0, sign * int(jittered))
            await asyncio.sleep(random.uniform(0.1, 0.4))

        # Pause to "read"
        await asyncio.sleep(HumanBehavior.scroll_delay())

    @staticmethod
    async def random_mouse_wander(page, duration_seconds: float = 2.0):
        """Move mouse randomly to simulate natural hand movement."""
        viewport = page.viewport_size or {"width": 1440, "height": 900}
        steps = int(duration_seconds * 10)
        for _ in range(steps):
            x = random.randint(50, viewport["width"] - 50)
            y = random.randint(50, viewport["height"] - 50)
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.05, 0.2))


# ── Anti-bot detection init scripts ──

STEALTH_INIT_SCRIPT = """
// ── RedTeam_AI Stealth Patches ──
// Adapted from playwright-stealth / puppeteer-extra-plugin-stealth

// 1. Clear navigator.webdriver
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// 2. Fake chrome runtime
window.chrome = {
    runtime: {},
    loadTimes: function() {},
    csi: function() {},
    app: {},
};

// 3. Fake plugins
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [1, 2, 3, 4, 5];
        plugins.item = (i) => plugins[i];
        plugins.namedItem = (name) => null;
        plugins.refresh = () => {};
        return plugins;
    }
});

// 4. Fake languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['zh-CN', 'zh', 'en-US', 'en']
});

// 5. Bypass permission queries
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission, onchange: null })
        : originalQuery(parameters)
);

// 6. Override toString to hide modifications
const originalToString = Function.prototype.toString;
Function.prototype.toString = function() {
    if (this === window.chrome.runtime ||
        this === window.chrome.csi ||
        this === window.chrome.loadTimes) {
        return 'function() { [native code] }';
    }
    return originalToString.call(this);
};

// 7. Spoof WebGL vendor
const getParameterProto = WebGLRenderingContext.prototype.getParameter;
// Only spoof when not already done
if (!window.__stealth_webgl_patched) {
    WebGLRenderingContext.prototype.getParameter = function(pname) {
        // UNMASKED_VENDOR_WEBGL
        if (pname === 37445) return 'Google Inc. (Intel)';
        // UNMASKED_RENDERER_WEBGL
        if (pname === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0)';
        return getParameterProto.call(this, pname);
    };
    window.__stealth_webgl_patched = true;
}

// 8. Spoof hardware concurrency
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 8
});

// 9. Spoof platform
Object.defineProperty(navigator, 'platform', {
    get: () => navigator.userAgent.includes('Win') ? 'Win32' : 'MacIntel'
});

// 10. Block automation detection probes
if (window.__proto__) {
    delete window.__proto__.__proto__.webdriver;
}
"""

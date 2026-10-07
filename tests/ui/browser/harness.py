"""Shared harness for the browser tests: a real `lovpn-ui` process in front of the TEST DOUBLE
broker (tests/ui/fake_broker.py). Nothing here is installed or shipped; it needs the optional
test-only packages listed in README.md (Playwright, axe-core)."""
import contextlib
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "..", "fake_broker.py")


class Window:
    def __init__(self, ui_binary, scenario="protected"):
        self.dir = tempfile.mkdtemp(prefix="lovpn-ui-test-")
        self.socket = os.path.join(self.dir, "broker.sock")
        self.url_file = os.path.join(self.dir, "url")
        self.scenario_file = self.socket + ".scenario"
        self.broker = subprocess.Popen([sys.executable, FAKE, self.socket, scenario],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(self.socket):
                break
            time.sleep(0.05)
        self.set_scenario(scenario)
        self.ui = subprocess.Popen([ui_binary, "--socket", self.socket, "--no-open", "--url-file", self.url_file],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(self.url_file) and os.path.getsize(self.url_file):
                break
            time.sleep(0.05)
        self.url = open(self.url_file).read().strip()

    def set_scenario(self, name):
        with open(self.scenario_file, "w") as handle:
            handle.write(name)

    def close(self):
        for process in (self.ui, self.broker):
            process.terminate()
            with contextlib.suppress(Exception):
                process.wait(timeout=5)


def require(condition, description):
    if not condition:
        raise AssertionError(description)
    print(f"PASS: {description}", flush=True)

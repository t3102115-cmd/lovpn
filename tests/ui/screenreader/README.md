# Orca run (manual aid, not a CI test)

Starts a private D-Bus session with its own AT-SPI bus, Orca 50 with speech sent to a dummy
module (silent), the test-double broker, `lovpn-ui` and Firefox, then moves focus through the
window over Marionette and reads what Orca *would have spoken* from its debug log.

```bash
T=$(mktemp -d)
dbus-run-session -- bash tests/ui/screenreader/inner.sh "$T" target/debug/lovpn-ui "$PWD"
grep "SPEECH OUTPUT" "$T/orca.log"
```

Needs Orca, Firefox, `at-spi-bus-launcher`, `at-spi2-registryd` and a Wayland or X session.
It opens a visible Firefox window for about two minutes. It is flaky: if Firefox is not
activated by the compositor Orca says nothing; run it again. It proves what Orca reads, not
what a person with a screen reader experiences.

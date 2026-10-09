set -u
# usage: inner.sh TMPDIR PATH/TO/lovpn-ui REPO_ROOT (run inside dbus-run-session)
T=$1; UI=$2; REPO=$3
export XDG_CONFIG_HOME=$T/config XDG_DATA_HOME=$T/data XDG_CACHE_HOME=$T/cache XDG_STATE_HOME=$T/state
mkdir -p $XDG_CONFIG_HOME/speech-dispatcher $XDG_DATA_HOME $XDG_CACHE_HOME $XDG_STATE_HOME $T/ff
cat > $XDG_CONFIG_HOME/speech-dispatcher/speechd.conf <<'C'
AddModule "dummy" "sd_dummy" "" ""
DefaultModule dummy
C
export GNOME_ACCESSIBILITY=1 MOZ_ENABLE_WAYLAND=1 NO_AT_BRIDGE=0
gsettings set org.gnome.desktop.interface toolkit-accessibility true 2>/dev/null
/usr/libexec/at-spi-bus-launcher --launch-immediately >$T/atspi.out 2>&1 &
sleep 2
/usr/libexec/at-spi2-registryd >$T/registry.out 2>&1 &
sleep 2
python3 $REPO/tests/ui/fake_broker.py $T/b.sock protected >/dev/null 2>&1 &
sleep 1
$UI --socket $T/b.sock --no-open --url-file $T/url >/dev/null 2>&1 &
sleep 1
orca --replace --debug --debug-file=$T/orca.log >$T/orca.out 2>&1 &
sleep 4
cat > $T/ff/user.js <<'C'
user_pref("accessibility.force_disabled", 0);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "about:blank");
C
firefox --no-remote --profile $T/ff --marionette about:blank >$T/ff.out 2>&1 &
python3 $REPO/tests/ui/screenreader/drive.py $T
kill $(jobs -p) 2>/dev/null

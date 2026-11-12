#!/bin/sh
# Install a locally built or independently verified release binary. Download and
# release-signature verification are handled by the signed release bootstrap.
set -eu
umask 077

fail() { echo "Latch: $*" >&2; exit 1; }
usage() {
  echo 'Usage: install.sh install|upgrade --binary PATH [--allow-downgrade] [-- SETUP_ARGUMENTS]'
  echo '       install.sh uninstall'
  echo 'Uninstall keeps /etc/latch and /var/lib/latch, including permanent bans.'
  exit 1
}

action=${1:-install}
if [ "$#" -gt 0 ]; then shift; fi
binary=
allow_downgrade=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
    --allow-downgrade) allow_downgrade=true; shift ;;
    --) shift; break ;;
    *) usage ;;
  esac
done
case "$action" in install|upgrade|uninstall) ;; *) usage ;; esac
[ "$(uname -s)" = Linux ] || fail 'This installer requires Linux with systemd.'
[ "$(id -u)" = 0 ] || fail 'Run this installer as root.'
for command in systemctl getent useradd install mktemp runuser stat cut grep; do
  command -v "$command" >/dev/null 2>&1 || fail "Required command is missing: $command"
done
[ -d /run/systemd/system ] || fail 'systemd must be running in this VM or container.'

target=/usr/local/bin/latch-server
unit=/etc/systemd/system/latch-server.service
configuration=/etc/latch/server.json
state=/var/lib/latch
backup=/usr/local/lib/latch/latch-server.previous
unit_backup=/usr/local/lib/latch/latch-server.service.previous
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary=
trap 'if [ -n "$temporary" ]; then rm -f -- "$temporary"; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ ! -L "$unit" ] || fail 'Refusing a symlinked service unit.'
if [ -f "$unit" ]; then
  grep -Fqx '# Managed by Latch installer.' "$unit" || fail 'An unmanaged latch-server.service already exists.'
elif [ -e "$target" ]; then
  fail 'An unmanaged server binary already exists. Move it explicitly before installing.'
fi

if [ "$action" = uninstall ]; then
  [ "$#" -eq 0 ] && [ -z "$binary" ] && [ "$allow_downgrade" = false ] || usage
  [ ! -L "$target" ] && [ ! -L "$backup" ] && [ ! -L "$unit_backup" ] || fail 'Refusing symlinked installation paths.'
  if [ -f "$unit" ]; then systemctl disable --now latch-server.service; fi
  rm -f -- "$unit" "$target" "$backup" "$unit_backup" /usr/local/share/doc/latch/DEPLOYMENT.md
  rmdir /usr/local/lib/latch /usr/local/share/doc/latch 2>/dev/null || true
  systemctl daemon-reload
  echo 'Latch removed. Configuration, certificate cache, security state and service account were preserved.'
  echo 'Delete them manually only if you intend to lose device enrollments, identity and permanent bans.'
  exit 0
fi

[ -n "$binary" ] && [ -f "$binary" ] && [ -x "$binary" ] || fail 'Supply --binary with a built or verified executable.'
case "$binary" in /*) ;; *) binary="$(pwd)/$binary" ;; esac
case "$("$binary" version)" in 'Latch Server '*) ;; *) fail 'The supplied executable is not a Latch server.' ;; esac
[ -f "$script_dir/latch-server.service" ] || fail 'The service unit must accompany this script.'
for directory in /etc/latch "$state" /usr/local/lib/latch; do
  [ ! -L "$directory" ] || fail "Refusing symlinked directory: $directory"
  if [ -e "$directory" ]; then
    [ -d "$directory" ] && [ "$(stat -c %a "$directory")" = 700 ] || fail "Expected private directory mode 0700: $directory"
  else
    install -d -m 0700 "$directory"
  fi
done
[ ! -L "$configuration" ] && [ ! -L "$target" ] && [ ! -L "$backup" ] && [ ! -L "$unit_backup" ] || fail 'Refusing symlinked installation paths.'
if getent passwd latch >/dev/null; then
  [ "$(id -u latch)" != 0 ] || fail 'The latch account must be unprivileged.'
  [ "$(getent passwd latch | cut -d: -f6)" = /var/lib/latch ] || fail 'An unrelated latch account already exists.'
  case "$(getent passwd latch | cut -d: -f7)" in */nologin|*/false) ;; *) fail 'The existing latch account has an interactive shell.' ;; esac
else
  useradd --system --user-group --home-dir /var/lib/latch --no-create-home --shell /usr/sbin/nologin latch
fi

if [ "$action" = upgrade ]; then
  [ "$#" -eq 0 ] || usage
  [ -f "$configuration" ] && [ -f "$target" ] && [ -f "$unit" ] || fail 'Upgrade requires an existing installation.'
elif [ ! -f "$configuration" ]; then
  "$binary" setup --config "$configuration" --state-dir "$state" "$@"
else
  [ "$#" -eq 0 ] || fail 'Existing configuration is preserved. Edit it explicitly to change deployment settings.'
fi

# Setup runs on root's controlling terminal. Transfer only known state files;
# never recursively change ownership of an operator-supplied directory tree.
[ ! -L "$state/state.db" ] && [ -f "$state/state.db" ] || fail 'Unsafe or missing security database.'
chown latch:latch /etc/latch "$configuration" "$state" "$state/state.db"
if [ -d "$state/acme" ]; then
  [ ! -L "$state/acme" ] || fail 'Unsafe ACME cache directory.'
  chown latch:latch "$state/acme"
fi
# Downloads live in a root-only temporary directory. Stage the verified image
# in the public binary directory before the unprivileged preflight; do not
# weaken permissions on the download or credentials directory.
if [ -f "$target" ] && [ "$allow_downgrade" = false ]; then
  installed=$("$target" version)
  case "$installed" in
    'Latch Server '*) installed=${installed#Latch Server } ;;
    *) fail 'Cannot determine the installed server version.' ;;
  esac
  "$binary" version --check-upgrade "$installed" || fail 'Software downgrade rejected. A deliberate local rollback requires --allow-downgrade.'
fi
temporary=$(mktemp /usr/local/bin/.latch-server.XXXXXX)
install -m 0755 "$binary" "$temporary"
runuser -u latch -- "$temporary" doctor --config "$configuration"

if [ -f "$target" ]; then install -m 0700 "$target" "$backup"; fi
if [ -f "$unit" ]; then install -m 0600 "$unit" "$unit_backup"; fi
mv -f -- "$temporary" "$target"
temporary=
install -m 0644 "$script_dir/latch-server.service" "$unit"
install -d -m 0755 /usr/local/share/doc/latch
if [ -f "$script_dir/../../docs/DEPLOYMENT.md" ]; then
  install -m 0644 "$script_dir/../../docs/DEPLOYMENT.md" /usr/local/share/doc/latch/DEPLOYMENT.md
fi
systemctl daemon-reload
systemctl enable latch-server.service
systemctl reset-failed latch-server.service >/dev/null 2>&1 || true
if systemctl restart latch-server.service && systemctl is-active --quiet latch-server.service; then
  :
else
  if [ "$action" = upgrade ] && [ -f "$backup" ] && [ -f "$unit_backup" ]; then
    install -m 0755 "$backup" "$target"
    install -m 0644 "$unit_backup" "$unit"
    systemctl daemon-reload
    systemctl reset-failed latch-server.service >/dev/null 2>&1 || true
    systemctl restart latch-server.service || true
    fail 'Upgrade failed; restored the previous binary. Inspect systemctl status latch-server.'
  fi
  fail 'Service startup failed. Inspect systemctl status latch-server.'
fi
echo 'Latch server installed. Use: systemctl status latch-server'
echo 'Local recovery: sudo /usr/local/bin/latch-server admin reset --config /etc/latch/server.json'
echo 'No firewall or reverse-proxy configuration was changed.'

#!/bin/sh
# Run only after this script's detached signature has been verified with an
# independently trusted publisher public key. Never trust a key from the mirror.
set -eu
umask 077
fail() { echo "Latch: $*" >&2; exit 1; }
usage() {
  echo 'Usage: install.sh --repository HTTPS_URL --publisher-key FILE --server HTTPS_URL'
  echo '       [--bin-dir DIR] [--config-dir DIR] [--nick NAME] [--identity-backend file|keychain]'
  echo '       [--non-interactive --enrollment-fd FD] [--no-start] [--dev]'
  echo '       --component server [--upgrade] [-- SERVER_SETUP_ARGUMENTS]'
  exit 1
}
repository=
publisher_key=
server=
bin_dir=${HOME:?}/.local/bin
configuration=
nickname=
nick_set=false
backend=
noninteractive=false
enrollment_fd=
no_start=false
development=false
component=client
server_action=install
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository) [ "$#" -ge 2 ] || usage; repository=$2; shift 2 ;;
    --publisher-key) [ "$#" -ge 2 ] || usage; publisher_key=$2; shift 2 ;;
    --server) [ "$#" -ge 2 ] || usage; server=$2; shift 2 ;;
    --bin-dir) [ "$#" -ge 2 ] || usage; bin_dir=$2; shift 2 ;;
    --config-dir) [ "$#" -ge 2 ] || usage; configuration=$2; shift 2 ;;
    --nick) [ "$#" -ge 2 ] || usage; nickname=$2; nick_set=true; shift 2 ;;
    --identity-backend) [ "$#" -ge 2 ] || usage; backend=$2; shift 2 ;;
    --enrollment-fd) [ "$#" -ge 2 ] || usage; enrollment_fd=$2; shift 2 ;;
    --non-interactive) noninteractive=true; shift ;;
    --no-start) no_start=true; shift ;;
    --dev) development=true; shift ;;
    --component) [ "$#" -ge 2 ] || usage; component=$2; shift 2 ;;
    --upgrade) server_action=upgrade; shift ;;
    --) shift; break ;;
    *) usage ;;
  esac
done
case "$component" in client|server) ;; *) usage ;; esac
if [ "$component" = client ]; then
  [ "$#" -eq 0 ] && [ "$server_action" = install ] || usage
else
  [ "$no_start" = false ] && [ "$nick_set" = false ] && [ -z "$configuration$backend$enrollment_fd$server" ] && [ "$development" = false ] && [ "$noninteractive" = false ] || fail 'Client onboarding flags do not apply to server installation. Put server setup flags after --.'
fi
case "$repository" in https://?*) ;; *) fail 'Supply an explicit HTTPS release repository.' ;; esac
case "$repository" in *'@'*|*'?'*|*'#'*|*'%'*|*'..'*|*'\'*) fail 'Unsafe release repository URL.' ;; esac
if printf '%s' "$repository" | LC_ALL=C grep -q '[[:space:][:cntrl:]]'; then fail 'Unsafe release repository URL.'; fi
repository=${repository%/}
[ -f "$publisher_key" ] && [ ! -L "$publisher_key" ] || fail 'Supply an independently verified regular publisher public-key file.'
[ "$(wc -c < "$publisher_key")" -le 16384 ] || fail 'Publisher key is too large.'
if [ "$component" = client ] && [ "$no_start" = false ]; then [ -n "$server" ] || fail 'Supply --server for onboarding.'; fi
if [ -n "$enrollment_fd" ]; then
  case "$enrollment_fd" in *[!0-9]*|'') fail 'Invalid enrollment descriptor.' ;; esac
  [ "${#enrollment_fd}" -le 6 ] && [ "$enrollment_fd" -ge 3 ] || fail 'Enrollment descriptor must be at least 3.'
fi
if [ "$noninteractive" = true ] && [ "$no_start" = false ]; then
  [ -n "$enrollment_fd" ] || fail 'Noninteractive enrollment requires --enrollment-fd.'
fi
for tool in openssl curl mktemp awk grep wc date stat id; do command -v "$tool" >/dev/null 2>&1 || fail "Missing required installer tool: $tool"; done
case "$(uname -s)" in
  Darwin) platform=darwin ;;
  Linux) platform=linux ;;
  *) fail 'Supported platforms are macOS and Linux.' ;;
esac
if [ "$component" = server ]; then
  [ "$platform" = linux ] || fail 'Server installation requires Linux with systemd.'
  [ "$(id -u)" = 0 ] || fail 'Run the verified server bootstrap as root.'
fi
case "$(uname -m)" in arm64|aarch64) architecture=arm64 ;; x86_64|amd64) architecture=amd64 ;; *) fail 'Unsupported CPU architecture.' ;; esac
curl_bin=${LATCH_CURL_BIN:-curl}
if [ "$platform" = darwin ] && [ -z "${LATCH_CURL_BIN:-}" ]; then
  for candidate in /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl; do
    if [ -x "$candidate" ]; then curl_bin=$candidate; break; fi
  done
fi
temporary=$(mktemp -d "${TMPDIR:-/tmp}/latch-install.XXXXXX")
stage=
trap 'rm -rf -- "$temporary"; if [ -n "$stage" ]; then rm -f -- "$stage"; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
download() {
  "$curl_bin" --disable --fail --silent --show-error --proto '=https' --tlsv1.3 --connect-timeout 5 --max-time 120 --max-filesize "$2" "$repository/$1" -o "$temporary/$1" || fail 'Download failed. The installer requires a curl build with TLS 1.3 support.'
  [ "$(wc -c < "$temporary/$1")" -le "$2" ] || fail 'Download exceeded its limit.'
}
download manifest.txt 32768
download manifest.sig 1024
openssl dgst -sha256 -verify "$publisher_key" -signature "$temporary/manifest.sig" "$temporary/manifest.txt" >/dev/null 2>&1 || fail 'Release manifest signature verification failed.'
[ "$(head -n 1 "$temporary/manifest.txt")" = 'Latch-Release 1' ] || fail 'Unsupported release manifest.'
version=$(awk '$1=="Version" && NF==2 {count++; value=$2} END {if(count!=1) exit 1; print value}' "$temporary/manifest.txt") || fail 'Invalid release version.'
printf '%s\n' "$version" | LC_ALL=C grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || fail 'Invalid release version.'
[ "${#version}" -le 40 ] || fail 'Release version is too long.'
printf '%s\n' "$version" | awk -F. '{for(i=1;i<=3;i++) if($i>4294967295) exit 1}' || fail 'Release version component is too large.'
source_commit=$(awk '$1=="Source" && NF==2 {count++; value=$2} END {if(count!=1 || length(value)!=40 || value ~ /[^0-9a-f]/) exit 1; print value}' "$temporary/manifest.txt") || fail 'Invalid source commit.'
expires=$(awk '$1=="Expires" && NF==2 {count++; value=$2} END {if(count!=1) exit 1; print value}' "$temporary/manifest.txt") || fail 'Invalid manifest expiration.'
case "$expires" in ''|*[!0-9]*) fail 'Invalid manifest expiration.' ;; esac
[ "${#expires}" -le 12 ] || fail 'Invalid manifest expiration.'
now=$(date +%s)
[ "$expires" -gt "$now" ] && [ "$expires" -le "$((now+691200))" ] || fail 'Release manifest is expired or its lifetime is excessive.'
checksum() {
  awk -v name="$1" '$1=="SHA256" && $3==name && NF==3 {count++; value=$2} END {if(count!=1 || length(value)!=64 || value ~ /[^0-9a-f]/) exit 1; print value}' "$temporary/manifest.txt"
}
# Tie this authenticated script to the fresh manifest as well. A stale signed
# script cannot silently install from a newer release's different bootstrap.
[ -f "$0" ] && [ ! -L "$0" ] || fail 'Run the verified script as a regular file.'
[ "$(wc -c < "$0")" -le 65536 ] || fail 'Bootstrap script is too large.'
expected_script=$(checksum start.sh) || fail 'Manifest is missing its bootstrap checksum.'
[ "$(openssl dgst -sha256 "$0" | awk '{print $NF}')" = "$expected_script" ] || fail 'This bootstrap does not match the current signed manifest. Download and verify the matching script.'
verified_download() {
  expected=$(checksum "$1") || fail "Manifest does not contain one valid checksum for $1."
  download "$1" "$2"
  actual=$(openssl dgst -sha256 "$temporary/$1" | awk '{print $NF}')
  [ "$actual" = "$expected" ] || fail "Checksum verification failed for $1."
}
if [ "$component" = server ]; then artifact="latch-server-$platform-$architecture"; else artifact="latch-$platform-$architecture"; fi
verified_download "$artifact" 67108864
chmod 0700 "$temporary/$artifact"
if [ "$component" = server ]; then
  [ "$("$temporary/$artifact" version)" = "Latch Server $version" ] || fail 'Verified server reports the wrong version.'
  verified_download server-install.sh 65536
  verified_download latch-server.service 16384
  sh "$temporary/server-install.sh" "$server_action" --binary "$temporary/$artifact" -- "$@"
  exit 0
fi
[ "$("$temporary/$artifact" version)" = "Latch $version" ] || fail 'Verified client reports the wrong version.'
mkdir -p "$bin_dir"
[ -d "$bin_dir" ] && [ ! -L "$bin_dir" ] || fail 'Unsafe installation directory.'
if [ "$platform" = darwin ]; then
  owner=$(stat -f '%u' "$bin_dir"); permissions=$(stat -f '%Lp' "$bin_dir")
else
  owner=$(stat -c '%u' "$bin_dir"); permissions=$(stat -c '%a' "$bin_dir")
fi
[ "$owner" = "$(id -u)" ] && [ "$((0$permissions & 022))" -eq 0 ] || fail 'Install into a directory you own that is not writable by others.'
destination="$bin_dir/latch"
[ ! -L "$destination" ] || fail 'Refusing to replace a symlink.'
[ ! -e "$destination" ] || fail 'Latch is already installed at this path. Use latch update to verify and apply upgrades.'
stage=$(mktemp "$bin_dir/.latch.XXXXXX")
cp "$temporary/$artifact" "$stage"
chmod 0755 "$stage"
mv -f -- "$stage" "$destination"
stage=
echo "Installed Latch $version at $destination"
if [ "$no_start" = true ]; then exit 0; fi
set --
if [ "$noninteractive" = true ]; then set -- enroll; fi
set -- "$@" --server "$server" --update-url "$repository/updates"
if [ -n "$configuration" ]; then set -- "$@" --config-dir "$configuration"; fi
if [ "$nick_set" = true ]; then set -- "$@" --nick "$nickname"; fi
if [ -n "$backend" ]; then set -- "$@" --identity-backend "$backend"; fi
if [ -n "$enrollment_fd" ]; then set -- "$@" --enrollment-fd "$enrollment_fd"; fi
if [ "$development" = true ]; then set -- "$@" --dev; fi
# Enrollment happens only inside the authenticated binary. It reads /dev/tty or
# the explicit inherited descriptor, never a PIN argument or environment value.
"$destination" "$@"

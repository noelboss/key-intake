#!/bin/bash
# Tests for KeyIntake (write path headless against a throwaway keychain) and the key-intake wrapper.
# Run: bash tests/key-intake.test.sh — all values are fake; they are compared by hash, never printed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/app/KeyIntake.swift"
ICON="$ROOT/app/MakeIcon.swift"
PLIST="$ROOT/app/Info.plist"
WRAPPER="$ROOT/key-intake"
export KEY_INTAKE_ACCOUNT=ki-test
unset KEY_INTAKE_ON_STORE
S="$(mktemp -d "${TMPDIR:-/tmp}/key-intake-test.XXXXXX")"
mkdir -p "$S/kc"
KC="$S/kc/test.keychain-db"
BIN="$S/KeyIntake"
pass=0 fail=0

cleanup() {
	/usr/bin/security delete-keychain "$KC" >/dev/null 2>&1
	chmod -R u+rwx "$S" 2>/dev/null; rm -rf "$S"
}
trap cleanup EXIT

ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "  $2"; }
expect() { # name expected actual
	if [ "$2" = "$3" ]; then ok; else bad "$1" "expected [$2] got [$3]"; fi
}

fakeval() { /usr/bin/head -c 30 /dev/urandom | /usr/bin/base64 | tr -d '\n=' ; }
hex_of() { printf '%s' "$1" | xxd -p | tr -d '\n'; }
leaks() { # value text… → how many times the value or its hex shows up in the text on stdin
	local v="$1" h; h="$(hex_of "$1")"
	/usr/bin/grep -c -F -f <(printf '%s\n%s\n' "$v" "$h")
}
hash_of() { printf '%s' "$1" | /usr/bin/shasum -a 256 | cut -c1-64; }
stored_hash() { # name account → sha256 of the stored value
	/usr/bin/security find-generic-password -s "$1" -a "$2" -w "$KC" 2>/dev/null | tr -d '\n' | /usr/bin/shasum -a 256 | cut -c1-64
}
stored_hash_hex() { # security prints non-ASCII values as hex → decode first
	/usr/bin/security find-generic-password -s "$1" -a "$2" -w "$KC" 2>/dev/null | tr -d '\n' | xxd -r -p | /usr/bin/shasum -a 256 | cut -c1-64
}
count_entries() { /usr/bin/security dump-keychain "$KC" 2>/dev/null | /usr/bin/grep -c "\"svce\"<blob>=\"$1\""; }
seed() { # name account value
	/usr/bin/security add-generic-password -s "$1" -a "$2" -w "$3" "$KC" >/dev/null 2>&1
}
GUIDE=(--url "https://example.com/tokens/new" --steps "Token anlegen | Wert kopieren")
run() { # names → one guide group; stdin from $S/in → sets OUT, RC, ERR
	OUT="$("$BIN" "$@" "${GUIDE[@]}" --keychain "$KC" --stdin-values <"$S/in" 2>"$S/err")"
	RC=$?
	ERR="$(cat "$S/err")"
}

# Build once, headless
if ! swiftc -O -suppress-warnings "$SRC" -o "$BIN" 2>"$S/build.err"; then
	echo "build failed"; cat "$S/build.err"; exit 2
fi
/usr/bin/security create-keychain -p test-pass "$KC" >/dev/null 2>&1 || { echo "cannot create throwaway keychain"; exit 2; }
/usr/bin/security unlock-keychain -p test-pass "$KC" >/dev/null 2>&1
/usr/bin/security set-keychain-settings "$KC" >/dev/null 2>&1

# new name, 40 chars → stored, account ki-test, readable, same hash
V1="$(fakeval)"
printf 'KI_NEW\t%s\n' "$V1" >"$S/in"; run KI_NEW
expect "new: status line" "stored KI_NEW" "$OUT"
expect "new: exit 0" "0" "$RC"
expect "new: value roundtrip" "$(hash_of "$V1")" "$(stored_hash KI_NEW ki-test)"
expect "new: exactly one entry" "1" "$(count_entries KI_NEW)"
expect "new: stdout and stderr hold neither value nor its hex" "0" "$(printf '%s\n%s' "$OUT" "$ERR" | leaks "$V1")"

# existing under account other, replace confirmed → account kept, still one entry
seed KI_EXIST other "$(fakeval)"
V2="$(fakeval)"
printf 'KI_EXIST\t%s\treplace\n' "$V2" >"$S/in"; run KI_EXIST
expect "replace: status" "stored KI_EXIST" "$OUT"
expect "replace: account other kept" "$(hash_of "$V2")" "$(stored_hash KI_EXIST other)"
expect "replace: still one entry" "1" "$(count_entries KI_EXIST)"

# existing, replace not confirmed → skipped, unchanged
OLD="$(fakeval)"
seed KI_KEEP other "$OLD"
printf 'KI_KEEP\t%s\n' "$(fakeval)" >"$S/in"; run KI_KEEP
expect "keep: status" "skipped KI_KEEP" "$OUT"
expect "keep: exit 1" "1" "$RC"
expect "keep: value unchanged" "$(hash_of "$OLD")" "$(stored_hash KI_KEEP other)"

# ambiguous: two entries, same name → failed, none touched
A1="$(fakeval)"; A2="$(fakeval)"
seed KI_DUP other "$A1"; seed KI_DUP ki-test "$A2"
printf 'KI_DUP\t%s\treplace\n' "$(fakeval)" >"$S/in"; run KI_DUP
expect "ambiguous: status" "failed KI_DUP ambiguous" "$OUT"
expect "ambiguous: exit 2" "2" "$RC"
expect "ambiguous: first untouched" "$(hash_of "$A1")" "$(stored_hash KI_DUP other)"
expect "ambiguous: second untouched" "$(hash_of "$A2")" "$(stored_hash KI_DUP ki-test)"

# KEY_INTAKE_ACCOUNT unset → new entries go under the user name
VD="$(fakeval)"
printf 'KI_DEFAULT\t%s\n' "$VD" >"$S/in"
OUT="$(KEY_INTAKE_ACCOUNT= "$BIN" KI_DEFAULT "${GUIDE[@]}" --keychain "$KC" --stdin-values <"$S/in" 2>&1)"
expect "default account: stored" "stored KI_DEFAULT" "$OUT"
expect "default account: user name" "$(hash_of "$VD")" "$(stored_hash KI_DEFAULT "$(id -un)")"

# empty value → skipped, nothing created; all empty → exit 1
printf 'KI_EMPTY\t\n' >"$S/in"; run KI_EMPTY
expect "empty: status" "skipped KI_EMPTY" "$OUT"
expect "empty: exit 1" "1" "$RC"
expect "empty: no entry" "0" "$(count_entries KI_EMPTY)"
printf 'KI_WS\t   \n' >"$S/in"; run KI_WS
expect "whitespace only: skipped" "skipped KI_WS" "$OUT"

# trailing newline stripped
V3="$(fakeval)"
printf 'KI_NL\t%s\\n\n' "$V3" >"$S/in"; run KI_NL
expect "newline: stored" "stored KI_NL" "$OUT"
expect "newline: stripped before storing" "$(hash_of "$V3")" "$(stored_hash KI_NL ki-test)"

# special characters survive the hex path
V4='a"b'"'"'c\d é€ 🔑 x  y;$(id)`z`'
printf 'KI_SPECIAL\t%s\n' "$V4" >"$S/in"; run KI_SPECIAL
expect "special: stored" "stored KI_SPECIAL" "$OUT"
expect "special: roundtrip (security prints non-ASCII as hex)" "$(hash_of "$V4")" "$(stored_hash_hex KI_SPECIAL ki-test)"

# long value over the hex path, up to the security -i line limit; beyond it a clear failure and nothing written
V5="$(/usr/bin/head -c 4000 /dev/urandom | /usr/bin/base64 | tr -d '\n=+/' | cut -c1-1900)"
printf 'KI_LONG\t%s\n' "$V5" >"$S/in"; run KI_LONG
expect "long: stored" "stored KI_LONG" "$OUT"
expect "long: roundtrip" "$(hash_of "$V5")" "$(stored_hash KI_LONG ki-test)"
V5B="$(/usr/bin/head -c 4000 /dev/urandom | /usr/bin/base64 | tr -d '\n=+/' | cut -c1-2100)"
printf 'KI_TOOLONG\t%s\n' "$V5B" >"$S/in"; run KI_TOOLONG
expect "too long: exact message, no length in it" "failed KI_TOOLONG value too long" "$OUT"
expect "too long: exit 2" "2" "$RC"
expect "too long: nothing written" "0" "$(count_entries KI_TOOLONG)"

# several names in one run, order kept
V6="$(fakeval)"
printf 'KI_M2\t%s\n' "$V6" >"$S/in"; run KI_M1 KI_M2 KI_M3
expect "multi: lines in argument order" "skipped KI_M1
stored KI_M2
skipped KI_M3" "$OUT"
expect "multi: exit 0" "0" "$RC"

# 128-char name
LONGNAME="KI_$(printf 'X%.0s' $(seq 1 125))"
printf '%s\t%s\n' "$LONGNAME" "$(fakeval)" >"$S/in"; run "$LONGNAME"
expect "128 char name: stored" "stored $LONGNAME" "$OUT"

# invalid names and arguments → exit 2, nothing written
before="$(/usr/bin/security dump-keychain "$KC" 2>/dev/null | /usr/bin/grep -c '"svce"')"
for bad_name in 'foo bar' ';rm' 'a/b' "$(printf 'X%.0s' $(seq 1 129))" '--help' '-h' '-KI_LEAD' '_KI_LEAD' '.KI_LEAD'; do
	printf '%s\t%s\n' "$bad_name" "$(fakeval)" >"$S/in"; run "$bad_name"
	expect "invalid name [$bad_name]: exit 2" "2" "$RC"
done
expect "invalid names: nothing written" "$before" "$(/usr/bin/security dump-keychain "$KC" 2>/dev/null | /usr/bin/grep -c '"svce"')"
printf 'KI_X\t%s\n' "$(fakeval)" | "$BIN" KI_X "${GUIDE[@]}" --stdin-values >/dev/null 2>&1; expect "stdin-values without keychain: exit 2" "2" "$?"
printf 'KI_X\t%s\n' "$(fakeval)" | "$BIN" KI_X "${GUIDE[@]}" --stdin-values --keychain "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
expect "stdin-values with login keychain: exit 2" "2" "$?"
"$BIN" KI_X "${GUIDE[@]}" --keychain "$KC" >/dev/null 2>&1; expect "keychain without stdin-values: exit 2" "2" "$?"
"$BIN" KI_X KI_X "${GUIDE[@]}" --keychain "$KC" --stdin-values </dev/null >/dev/null 2>&1; expect "duplicate name: exit 2" "2" "$?"

# guide: every NAME belongs to a group closed by --url (https) and --steps; several groups per call
printf 'KI_G1\t%s\nKI_G3\t%s\n' "$(fakeval)" "$(fakeval)" >"$S/in"
OUT="$("$BIN" KI_G1 KI_G2="Secret Access Key" --url https://example.com/a --steps "eins | zwei" KI_G3 --steps "drei" --url https://example.org/b?x=1#y --keychain "$KC" --stdin-values <"$S/in" 2>&1)"; RC=$?
expect "guide: two groups, lines in argument order" "stored KI_G1
skipped KI_G2
stored KI_G3" "$OUT"
expect "guide: two groups, exit 0" "0" "$RC"
before="$(/usr/bin/security dump-keychain "$KC" 2>/dev/null | /usr/bin/grep -c '"svce"')"
guide_fails() { # expected-message args… → exit 2, exact message on stderr, nothing written
	local want="$1"; shift
	printf 'KI_GX\t%s\nKI_GY\t%s\n' "$(fakeval)" "$(fakeval)" >"$S/in"
	OUT="$("$BIN" "$@" --keychain "$KC" --stdin-values <"$S/in" 2>"$S/err")"; RC=$?
	expect "guide [$*]: exit 2" "2" "$RC"
	expect "guide [$*]: message" "$want" "$(cat "$S/err")"
	expect "guide [$*]: no status line" "" "$OUT"
}
guide_fails "every NAME needs --url and --steps" KI_GX
guide_fails "every NAME needs --url and --steps" KI_GX --url https://example.com/a
guide_fails "every NAME needs --url and --steps" KI_GX --steps "eins"
guide_fails "every NAME needs --url and --steps" KI_GX --url https://example.com/a --steps "eins" KI_GY
guide_fails "every NAME needs --url and --steps" KI_GX --url https://example.com/a KI_GY --steps "eins"
guide_fails "--url and --steps follow the names they belong to" --url https://example.com/a --steps "eins" KI_GX
guide_fails "--url and --steps follow the names they belong to" KI_GX --url https://example.com/a --url https://example.com/b --steps "eins"
guide_fails "--url and --steps follow the names they belong to" KI_GX --url https://example.com/a --steps "eins" --steps "zwei"
for bad_url in 'http://example.com/a' 'file:///etc/passwd' 'javascript:alert(1)' 'https://' 'https:///a' 'https://exa mple.com' 'example.com/a' ''; do
	guide_fails "invalid url" KI_GX --url "$bad_url" --steps "eins"
done
for bad_steps in '' '   ' ' | | '; do
	guide_fails "--steps needs at least one step" KI_GX --url https://example.com/a --steps "$bad_steps"
done
guide_fails "--steps takes at most 12 steps" KI_GX --url https://example.com/a --steps "1|2|3|4|5|6|7|8|9|10|11|12|13"
guide_fails "--url needs a value" KI_GX --steps "eins" --url
expect "guide errors: nothing written" "$before" "$(/usr/bin/security dump-keychain "$KC" 2>/dev/null | /usr/bin/grep -c '"svce"')"

# write failure (keychain directory read-only; a locked keychain would raise a real unlock dialog) → failed line, exit 2, no value anywhere
V7="$(fakeval)"
chmod 444 "$KC"; chmod 555 "$S/kc"
printf 'KI_RO\t%s\n' "$V7" >"$S/in"; run KI_RO
chmod 755 "$S/kc"; chmod 644 "$KC"
case "$OUT" in failed\ KI_RO\ *) ok ;; *) bad "write failure: failed line" "got [$OUT]" ;; esac
expect "write failure: exit 2" "2" "$RC"
expect "write failure: no value or hex in output" "0" "$(printf '%s\n%s' "$OUT" "$ERR" | leaks "$V7")"

# the child process: argv is exactly ["-i"], the value only travels over stdin (a stand-in logs both and hands on to the real security)
cat >"$S/security-stub" <<STUB
#!/bin/sh
printf '%s:%s\n' "\$#" "\$*" >>"$S/stub.argv"
cat >"$S/stub.stdin"
exec /usr/bin/security "\$@" <"$S/stub.stdin"
STUB
chmod +x "$S/security-stub"
V8="$(fakeval)"
printf 'KI_PS\t%s\n' "$V8" >"$S/in"
: >"$S/stub.argv"
OUT="$(KEY_INTAKE_SECURITY="$S/security-stub" "$BIN" KI_PS "${GUIDE[@]}" --keychain "$KC" --stdin-values <"$S/in" 2>&1)"; RC=$?
expect "child: run still stored" "stored KI_PS" "$OUT"
expect "child: security got exactly one argument, -i" "1:-i" "$(cat "$S/stub.argv")"
expect "child: argv holds neither value nor hex" "0" "$(leaks "$V8" <"$S/stub.argv")"
expect "child: stdin carries the value as hex (the check can fail)" "1" "$(/usr/bin/grep -c -F "$(hex_of "$V8")" "$S/stub.stdin")"

# (a) existing entry without account: replace updates it in place, never a duplicate under ki-test
VA="$(fakeval)"
printf 'add-generic-password -s "KI_NOACCT" -a "" -X %s "%s"\n' "$(hex_of "$(fakeval)")" "$KC" | /usr/bin/security -i >/dev/null 2>&1
printf 'KI_NOACCT\t%s\treplace\n' "$VA" >"$S/in"; run KI_NOACCT
expect "no account: replace stored" "stored KI_NOACCT" "$OUT"
expect "no account: still one entry" "1" "$(count_entries KI_NOACCT)"
expect "no account: value replaced" "$(hash_of "$VA")" "$(stored_hash KI_NOACCT "")"

# (b) any lookup status except not-found locks the row
VB="$(fakeval)"
printf 'KI_LOCKED\t%s\n' "$VB" >"$S/in"
OUT="$(KEY_INTAKE_TEST_LOOKUP_STATUS=-128 "$BIN" KI_LOCKED "${GUIDE[@]}" --keychain "$KC" --stdin-values <"$S/in" 2>"$S/err")"; RC=$?
expect "lookup error: row locked" "failed KI_LOCKED lookup error" "$OUT"
expect "lookup error: exit 2" "2" "$RC"
expect "lookup error: nothing written" "0" "$(count_entries KI_LOCKED)"

# (c) test mode: absolute path only, judged by device/inode after opening
mkdir -p "$S/trap"; cp "$KC" "$S/trap/login.keychain-db"
printf 'KI_X\t%s\n' "$(fakeval)" >"$S/in"
OUT="$(cd "$S/trap" && "$BIN" KI_X "${GUIDE[@]}" --keychain login.keychain-db --stdin-values <"$S/in" 2>&1)"; expect "relative path: exit 2" "2" "$?"
expect "relative path: says why" "test mode needs an absolute keychain path" "$OUT"
ln -s "$HOME/Library/Keychains/login.keychain-db" "$S/alias.keychain-db"
"$BIN" KI_X "${GUIDE[@]}" --keychain "$S/alias.keychain-db" --stdin-values <"$S/in" >/dev/null 2>&1; expect "symlink to the login keychain: exit 2" "2" "$?"
ln "$HOME/Library/Keychains/login.keychain-db" "$S/hard.keychain-db" 2>/dev/null \
	&& { "$BIN" KI_X "${GUIDE[@]}" --keychain "$S/hard.keychain-db" --stdin-values <"$S/in" >/dev/null 2>&1; expect "hard link to the login keychain: exit 2" "2" "$?"; rm -f "$S/hard.keychain-db"; }

# (e) state changed between opening and saving: the app looks up at start, the entry appears while it waits on stdin
VE="$(fakeval)"
( sleep 1.5; seed KI_RACE other "$(fakeval)"; printf 'KI_RACE\t%s\n' "$VE" ) | "$BIN" KI_RACE "${GUIDE[@]}" --keychain "$KC" --stdin-values >"$S/race.out" 2>&1
expect "state changed: refused" "failed KI_RACE state changed" "$(cat "$S/race.out")"
expect "state changed: the entry that appeared is untouched" "1" "$(count_entries KI_RACE)"

# --- wrapper key-intake ---
WB="$S/wbin"
wrap() { # stdin from $S/in → sets OUT, ERR, RC
	OUT="$(KEY_INTAKE_BIN_DIR="$WB" "$@" <"$S/in" 2>"$S/err")"; RC=$?
	ERR="$(cat "$S/err")"
}
VW="$(fakeval)"
printf 'KI_W1\t%s\n' "$VW" >"$S/in"
wrap "$WRAPPER" KI_W1 KI_W2 "${GUIDE[@]}" --keychain "$KC" --stdin-values
expect "wrapper: status lines pass through" "stored KI_W1
skipped KI_W2" "$OUT"
expect "wrapper: exit code passes through" "0" "$RC"
expect "wrapper: no on-store hook → stderr empty" "" "$ERR"
expect "wrapper: value stored" "$(hash_of "$VW")" "$(stored_hash KI_W1 ki-test)"
WBIN="$WB/KeyIntake.app/Contents/MacOS/KeyIntake"
t1="$(stat -f %m "$WBIN")"
sleep 1.1
printf 'KI_W3\t\n' >"$S/in"
wrap "$WRAPPER" KI_W3 "${GUIDE[@]}" --keychain "$KC" --stdin-values
expect "wrapper: unchanged source → no rebuild" "$t1" "$(stat -f %m "$WBIN")"
expect "wrapper: nothing stored → exit 1" "1" "$RC"

cp "$SRC" "$S/KeyIntake.swift"; echo '// touched' >>"$S/KeyIntake.swift"
printf 'KI_W3\t\n' >"$S/in"
KEY_INTAKE_SRC="$S/KeyIntake.swift" wrap "$WRAPPER" KI_W3 "${GUIDE[@]}" --keychain "$KC" --stdin-values
[ "$(stat -f %m "$WBIN")" != "$t1" ] && ok || bad "wrapper: changed source → rebuild"
expect "wrapper: new hash saved" "$(cat "$S/KeyIntake.swift" "$ICON" "$PLIST" | /usr/bin/shasum -a 256 | cut -c1-64)" "$(cat "$WB/.source-hash")"

cp "$SRC" "$S/broken.swift"; echo 'this is not swift' >>"$S/broken.swift"
KEY_INTAKE_SRC="$S/broken.swift" wrap "$WRAPPER" KI_W3 "${GUIDE[@]}" --keychain "$KC" --stdin-values
expect "wrapper: compile error → exit 2" "2" "$RC"
case "$ERR" in *error*) ok ;; *) bad "wrapper: compile error message shown" "got [$ERR]" ;; esac
expect "wrapper: compile error → no window, no status line" "" "$OUT"

printf '#!/bin/sh\ntouch "%s/hook-ran"\n' "$S" >"$S/on-store.sh"; chmod +x "$S/on-store.sh"
printf 'KI_W4\t%s\n' "$(fakeval)" >"$S/in"
KEY_INTAKE_ON_STORE="$S/on-store.sh" wrap "$WRAPPER" KI_W4 "${GUIDE[@]}" --keychain "$KC" --stdin-values
sleep 1
[ -f "$S/hook-ran" ] && ok || bad "wrapper: stored + KEY_INTAKE_ON_STORE → hook runs"
expect "wrapper: hook runs quietly" "" "$ERR"
rm -f "$S/hook-ran"
printf 'KI_W4\t\n' >"$S/in"
KEY_INTAKE_ON_STORE="$S/on-store.sh" wrap "$WRAPPER" KI_W4 "${GUIDE[@]}" --keychain "$KC" --stdin-values
sleep 1
[ ! -f "$S/hook-ran" ] && ok || bad "wrapper: nothing stored → hook stays idle"

# called through a symlink (e.g. ~/.local/bin/key-intake) → still finds its sources
ln -s "$WRAPPER" "$S/linked-key-intake"
printf 'KI_W5\t\n' >"$S/in"
wrap "$S/linked-key-intake" KI_W5 "${GUIDE[@]}" --keychain "$KC" --stdin-values
expect "wrapper via symlink: runs" "skipped KI_W5" "$OUT"
expect "wrapper via symlink: exit 1" "1" "$RC"

wrap "$WRAPPER" 'bad name'
expect "wrapper: invalid name → exit 2" "2" "$RC"

# --help and names with a leading - never reach the binary: a stand-in with the current source hash records any start
HB="$S/help-bin"; mkdir -p "$HB"
EB="$S/empty-bin"
mkdir -p "$HB/KeyIntake.app/Contents/MacOS"
printf '#!/bin/sh\ntouch "%s/window-started"\n' "$S" >"$HB/KeyIntake.app/Contents/MacOS/KeyIntake"; chmod +x "$HB/KeyIntake.app/Contents/MacOS/KeyIntake"
cat "$SRC" "$ICON" "$PLIST" | /usr/bin/shasum -a 256 | cut -c1-64 | tr -d '\n' >"$HB/.source-hash"
for help_args in '--help' '-h' 'KI_H1 --help' 'KI_H1 -h --keychain /nonexistent'; do
	# shellcheck disable=SC2086
	WB="$HB" wrap "$WRAPPER" $help_args
	expect "wrapper [$help_args]: exit 0" "0" "$RC"
	case "$OUT" in "usage: key-intake NAME[=label] … --url <link> --steps"*) ok ;; *) bad "wrapper [$help_args]: usage on stdout" "got [$OUT]" ;; esac
	expect "wrapper [$help_args]: stderr empty" "" "$ERR"
done
for lead in '-KI_LEAD' '--foo' '_KI_LEAD' '.KI_LEAD=note'; do
	WB="$HB" wrap "$WRAPPER" "$lead"
	expect "wrapper [$lead]: exit 2" "2" "$RC"
	expect "wrapper [$lead]: invalid name" "invalid name" "$ERR"
done
# a call without --url / --steps stops with the usage before building or starting the window
for guide_args in 'KI_H1' 'KI_H1 --url --steps eins' 'KI_H1 --url https://example.com/a' 'KI_H1 --steps eins' 'KI_H1 --url http://example.com/a --steps eins' '--url https://example.com/a --steps eins KI_H1'; do
	# shellcheck disable=SC2086
	WB="$HB" wrap "$WRAPPER" $guide_args
	expect "wrapper [$guide_args]: exit 2" "2" "$RC"
	expect "wrapper [$guide_args]: no status line" "" "$OUT"
	case "$ERR" in *"usage: key-intake NAME[=label] … --url <link> --steps"*) ok ;; *) bad "wrapper [$guide_args]: usage on stderr" "got [$ERR]" ;; esac
done
WB="$EB" wrap "$WRAPPER" KI_H1
[ ! -e "$EB/KeyIntake.app" ] && ok || bad "wrapper: missing guide built the binary"

[ ! -e "$S/window-started" ] && ok || bad "wrapper: --help / leading - started the binary"
WB="$EB" wrap "$WRAPPER" --help
[ ! -e "$EB/KeyIntake.app" ] && ok || bad "wrapper: --help built the binary"
wrap "$WRAPPER"
expect "wrapper: no args → exit 2" "2" "$RC"

echo "key-intake: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

#!/usr/bin/env bash
#
# guest-workload-check.sh — P9 in-guest workload check. Runs inside a spike guest
# after guest-agent-bootstrap.sh has produced an attested guest-local spire-agent,
# fetches an SVID from the guest's LOCAL Workload API, asserts the SPIFFE ID, and
# then watches for a rotation.
#
# THROWAWAY spike tooling. Appendix C of SPIKE_PLAN.md classifies everything under
# spike/ as never merged as product code: deletable without loss, because the
# evidence it produces lives in the journal.
#
# ---------------------------------------------------------------------------
# WHAT THIS PROVES
# ---------------------------------------------------------------------------
# SPIKE_PLAN.md P9 step 3 and its acceptance: "an in-guest app obtains the
# expected SVID from a standard local Workload API", and "verify rotation". Both
# halves matter. Issuance alone shows the entry matched; rotation shows the guest
# agent holds a live relationship with the server rather than a one-shot
# credential, which is what the P10 restart and stale-credential cases build on.
#
# There is nothing spike-specific in the client: `spire-agent api fetch x509`
# speaks the ordinary SPIFFE Workload API over the guest's own socket. The fetch
# also verifies the SVID against the trust bundle before printing anything, so a
# successful fetch is a chain check too.
#
# ---------------------------------------------------------------------------
# ROOT IS NOT THE CLAIM — the non-root check
# ---------------------------------------------------------------------------
# The acceptance is that an in-guest APP gets its SVID from a standard local
# Workload API. An app is not root, so a root-only fetch proves the weaker thing:
# that a caller who can already reach every path in the guest can reach the
# socket. This script therefore runs the SAME standard client a second time as an
# unprivileged user and reports a SEPARATE verdict for it. Neither result stands
# in for the other, and a root PASS never hides a non-root failure: the run ends
# ERROR with exit 24 instead.
#
# The socket decision this depends on, recorded because it is load-bearing: SPIRE
# 1.15.2 chmods the Workload API socket itself to 0777 (observed live — the host
# agent's socket is srwxrwxrwx in evidence/p9/deploy-02-socket-exposure.txt), so
# reachability is decided by the DIRECTORIES above it. guest-agent-bootstrap.sh
# creates every component of the socket directory mode 0755 rather than
# inheriting its own umask 077. That is not an authorization decision: SPIRE
# authorizes a workload by attesting it (unix uid/gid/path selectors) against a
# registration entry, never by file mode.
#
# Issuance to a non-root caller additionally needs a registration entry whose
# selectors match that uid. The P9 guest entry is unix:uid:0, so an unmatched
# non-root fetch is reported as exactly that — reachable, not issued — with the
# entry command to fix it, never as a pass.
#
# ---------------------------------------------------------------------------
# SECRET HANDLING — Appendix D
# ---------------------------------------------------------------------------
# `spire-agent api fetch x509 -write` writes svid.N.pem, svid.N.key and
# bundle.N.pem. The .key is a workload PRIVATE KEY, so:
#
#   * the write directory is a tmpfs this script mounts itself, mode 0700, and it
#     is overwritten and unmounted before the script exits, on every path. On
#     tmpfs that is an overwrite plus an unlink, and tmpfs pages can be swapped:
#     it is NOT cryptographic erasure and this harness never calls it that;
#   * every key is overwritten as soon as the certificate has been read;
#   * the printed material is SPIFFE IDs, validity windows, serials and counts,
#     which Appendix D rule 3 permits; the CLI's own stdout is passed through a
#     filter that withholds any line containing a PEM private-key header or a long
#     base64 run, so a future CLI that starts printing material cannot leak
#     through this harness.
#
# ---------------------------------------------------------------------------
# THREE OUTCOMES (the P8 convention, unchanged)
# ---------------------------------------------------------------------------
#   PASS   the behavior under test was observed and was correct
#   FAIL   it was observed and was wrong: a different SPIFFE ID, or no rotation
#          after the renewal point had passed
#   ERROR  nothing was observed: a missing dependency, an unreachable Workload
#          API, a non-root caller that could not be served, or a rotation window
#          longer than this run is allowed to wait
#
# ---------------------------------------------------------------------------
# EXIT CODES
# ---------------------------------------------------------------------------
#   0   PASS
#   2   usage: no expected SPIFFE ID, an unexpected argument, a bad value
#   6   a required binary is missing inside the guest
#   7   no memory-backed work directory could be established
#   8   the fetched material could not be overwritten and unmounted; supersedes
#       every other code, including 0
#   10  the Workload API answered nothing usable — ERROR
#   20  the SVID's SPIFFE ID is not the expected value — FAIL
#   21  no rotation before the renewal point plus grace had passed — FAIL
#   22  the rotation window is longer than ROTATION_MAX_WAIT_SECONDS — ERROR
#   24  root was served but a NON-ROOT caller was not, so the phase's actual
#       claim is unproven — ERROR

set -euo pipefail
umask 077

# --- Parameters ---------------------------------------------------------------

SPIRE_AGENT_BIN="${SPIRE_AGENT_BIN:-spire-agent}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

SOCKET_PATH="${SOCKET_PATH:-/tmp/spire-agent/public/api.sock}"
EXPECTED_SPIFFE_ID="${EXPECTED_SPIFFE_ID:-}"
FETCH_TIMEOUT="${FETCH_TIMEOUT:-10s}"

WORK_MOUNT="${WORK_MOUNT:-/run/spike-workload-check}"
WORK_TMPFS_SIZE="${WORK_TMPFS_SIZE:-1m}"
ALLOW_NON_TMPFS_WORKDIR="${ALLOW_NON_TMPFS_WORKDIR:-0}"

# poll   fetch twice around the renewal point and compare certificate serials
# watch  run `api watch` under a bounded timeout and count updates (no serials)
# skip   assert issuance only — an explicit opt-out that is NOT complete evidence
ROTATION_MODE="${ROTATION_MODE:-poll}"
ROTATION_MAX_WAIT_SECONDS="${ROTATION_MAX_WAIT_SECONDS:-900}"
ROTATION_POLL_INTERVAL="${ROTATION_POLL_INTERVAL:-15}"
ROTATION_GRACE_SECONDS="${ROTATION_GRACE_SECONDS:-30}"
# Minimum time to keep polling past the renewal point before calling it a FAIL.
ROTATION_MIN_WAIT_SECONDS="${ROTATION_MIN_WAIT_SECONDS:-45}"

# The non-root half of the acceptance claim.
#   run   (default) create or reuse an unprivileged user and fetch as that user
#   skip  explicit opt-out; the run then proves only the root case and says so
NONROOT_CHECK="${NONROOT_CHECK:-run}"
NONROOT_USER="${NONROOT_USER:-spike-workload}"
# The SPIFFE ID the NON-ROOT caller must receive. It defaults to the root one,
# which only matches if the registration entry's selectors cover that uid; the
# P9 entry is unix:uid:0, so a separate entry is normally registered for this.
NONROOT_EXPECTED_SPIFFE_ID="${NONROOT_EXPECTED_SPIFFE_ID:-}"

# --- State --------------------------------------------------------------------

WORK_DIR=""
MOUNTED=0
TRAP_DONE=0
RECLAIMED="not-attempted"
FETCH_ID=""
FETCH_SERIAL=""
FETCH_NOT_BEFORE=""
FETCH_NOT_AFTER=""
FIRST_SERIAL=""
SECOND_SERIAL=""
SELF_UID=""
CALLER_LABEL=""
NONROOT_UID=""
NONROOT_ID=""
NONROOT_SERIAL=""
NONROOT_VERDICT="not-attempted"
RUNUSER_BIN=""

# --- Helpers ------------------------------------------------------------------

log() {
	printf '%s\n' "$*"
}

warn() {
	printf 'WARNING: %s\n' "$*" >&2
}

die() {
	local code="$1"
	shift
	printf 'ERROR: %s\n' "$*" >&2
	exit "$code"
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 && return 0
	log "RESULT check=workload outcome=ERROR reason=missing_dependency dependency=$1"
	die 6 "$2 not found inside this guest: $1 (install it, or override with $3)"
}

is_mounted() {
	awk -v d="$1" '$2 == d { hit = 1 } END { exit hit ? 0 : 1 }' /proc/self/mounts
}

# safe_print echoes another program's stdout without becoming a leak path: a line
# carrying a PEM private-key header, or a long line that is nothing but base64, is
# withheld. The base64 test is written as a length comparison plus an anchored
# character class rather than as an {n,} interval, because mawk — the default awk
# on Debian, which is what the guests run — matches an open-ended interval against
# anything, and a filter that withholds every line is not a filter.
safe_print() {
	local prefix="$1" file="$2"
	[[ -s "$file" ]] || return 0
	awk -v p="$prefix" '
		/PRIVATE KEY/ { print p ": <line withheld: possible key material>"; next }
		length($0) >= 64 && $0 ~ /^[[:space:]]*[A-Za-z0-9+\/=]+[[:space:]]*$/ {
			print p ": <line withheld: possible key material>"; next
		}
		{ print p ": " $0 }
	' "$file"
}

spiffe_id_of_leaf() {
	local pem="$1" found
	found=$("$OPENSSL_BIN" x509 -in "$pem" -noout -text 2>/dev/null |
		grep -o 'URI:spiffe://[^,[:space:]]*' | head -n 1) || return 1
	printf '%s' "${found#URI:}"
}

# epoch_of converts an openssl date ("Aug 17 07:00:00 2026 GMT") to seconds.
epoch_of() {
	date -u -d "$1" +%s 2>/dev/null || printf ''
}

# --- Memory-backed storage ----------------------------------------------------

mount_work_tmpfs() {
	local dir="$WORK_MOUNT"

	if is_mounted "$dir"; then
		reclaim_files "$dir"
		MOUNTED=1
	else
		mkdir -p -- "$dir" || die 7 "cannot create $dir"
		chmod 0700 -- "$dir"
		if mount -t tmpfs -o "size=$WORK_TMPFS_SIZE,mode=0700,nosuid,nodev,noexec" tmpfs "$dir" 2>/dev/null; then
			MOUNTED=1
		elif [[ "$ALLOW_NON_TMPFS_WORKDIR" == "1" ]]; then
			warn "cannot mount tmpfs at $dir and ALLOW_NON_TMPFS_WORKDIR=1: fetched workload keys will"
			warn "touch whatever filesystem backs $dir. They are still shredded, but record this."
		else
			log "RESULT check=workload outcome=ERROR reason=tmpfs_mount_failed dir=$dir"
			die 7 "cannot mount tmpfs at $dir; the Workload API fetch writes a private key, so this script refuses a disk-backed work directory (override with ALLOW_NON_TMPFS_WORKDIR=1)"
		fi
	fi

	local fstype
	fstype=$(stat -f -c %T -- "$dir" 2>/dev/null || printf 'unknown')
	if [[ "$fstype" != "tmpfs" && "$ALLOW_NON_TMPFS_WORKDIR" != "1" ]]; then
		log "RESULT check=workload outcome=ERROR reason=workdir_not_tmpfs fstype=$fstype"
		die 7 "$dir is $fstype, not tmpfs"
	fi

	chmod 0700 -- "$dir"
	WORK_DIR="$dir"
	log "workdir: $dir fstype=$fstype mode=0700"
}

# reclaim_files overwrites and unlinks every file under a directory. On tmpfs that
# is an overwrite of pages plus an unlink, and tmpfs pages can have been swapped
# out before the overwrite: it is NOT cryptographic erasure (Appendix D rule 2).
reclaim_files() {
	local dir="$1"
	[[ -d "$dir" ]] || return 0
	find "$dir" -type f -exec shred -u -z -n 1 -- {} + 2>/dev/null || true
	find "$dir" -mindepth 1 -delete 2>/dev/null || true
	return 0
}

# reclaim_workdir overwrites and unmounts, then verifies both. The verified end
# state is "no files, no mount"; see reclaim_files for what that does not mean.
reclaim_workdir() {
	local dir="$WORK_MOUNT"

	# main reclaims explicitly so the RESULT line reports an observed end state;
	# the EXIT trap then calls this again. Report once.
	if [[ "$RECLAIMED" == "shredded-and-unmounted" ]] && ((MOUNTED == 0)); then
		return 0
	fi

	reclaim_files "$dir"

	local failures=()
	if ((MOUNTED == 1)) && is_mounted "$dir"; then
		umount -- "$dir" 2>/dev/null || umount -l -- "$dir" 2>/dev/null || true
		is_mounted "$dir" && failures+=("still mounted: $dir")
	fi
	if [[ -d "$dir" ]]; then
		local leftovers
		leftovers=$(find "$dir" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')
		[[ "$leftovers" == "0" ]] || failures+=("$leftovers file(s) left under $dir")
	fi

	if ((${#failures[@]} > 0)); then
		RECLAIMED="failed"
		local f
		for f in "${failures[@]}"; do
			warn "fetched workload material was NOT reclaimed: $f"
		done
		warn "run this by hand now: find $dir -type f -exec shred -u -z -n 1 {} + && umount $dir"
		return 1
	fi

	MOUNTED=0
	RECLAIMED="shredded-and-unmounted"
	log "workdir: files overwritten, $dir unmounted, and both verified — overwrite plus unlink on tmpfs, NOT cryptographic erasure"
	return 0
}

on_exit() {
	local status=$?
	((TRAP_DONE)) && return
	TRAP_DONE=1
	if ! reclaim_workdir; then
		log "RESULT check=workload outcome=ERROR reason=workdir_not_reclaimed material=live exit_was=$status"
		exit 8
	fi
	exit "$status"
}

# --- Workload API -------------------------------------------------------------

# fetch_svid calls the standard Workload API and fills FETCH_*. The private key
# the CLI writes is shredded as soon as the certificate has been parsed: this
# harness needs the certificate, never the key.
fetch_svid() {
	# Two statements, not one `local a=… b=…`: word expansion happens before the
	# builtin assigns, so the second value cannot reference the first under set -u.
	local label="$1"
	local dir="$WORK_DIR/$label"

	rm -rf -- "$dir"
	mkdir -p -- "$dir"
	chmod 0700 -- "$dir"

	local rc=0
	"$SPIRE_AGENT_BIN" api fetch x509 \
		-socketPath "$SOCKET_PATH" \
		-timeout "$FETCH_TIMEOUT" \
		-write "$dir" >"$dir/fetch.out" 2>&1 || rc=$?

	safe_print "fetch[$label]" "$dir/fetch.out"

	if ((rc != 0)); then
		return 1
	fi

	local svid="$dir/svid.0.pem"
	if [[ ! -s "$svid" ]]; then
		return 1
	fi

	FETCH_ID=$(spiffe_id_of_leaf "$svid" || printf '')
	FETCH_SERIAL=$("$OPENSSL_BIN" x509 -in "$svid" -noout -serial 2>/dev/null | cut -d= -f2)
	FETCH_NOT_BEFORE=$("$OPENSSL_BIN" x509 -in "$svid" -noout -startdate 2>/dev/null | cut -d= -f2-)
	FETCH_NOT_AFTER=$("$OPENSSL_BIN" x509 -in "$svid" -noout -enddate 2>/dev/null | cut -d= -f2-)

	# The workload key has served no purpose here beyond proving the API returned
	# a complete SVID. It goes now, not at the end of the run.
	find "$dir" -name '*.key' -type f -exec shred -u -z -n 1 -- {} + 2>/dev/null || true

	local bundle_certs
	# grep -c prints 0 and exits 1 with no match, so `|| true` keeps that 0 rather
	# than appending a second one.
	bundle_certs=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$dir/bundle.0.pem" 2>/dev/null || true)
	bundle_certs="${bundle_certs:-0}"

	log "svid[$label]: spiffe_id=${FETCH_ID:-<absent>}"
	log "svid[$label]: serial=${FETCH_SERIAL:--} not_before=${FETCH_NOT_BEFORE:--} not_after=${FETCH_NOT_AFTER:--}"
	log "svid[$label]: bundle_certs=$bundle_certs key=<shredded, never printed>"

	[[ -n "$FETCH_ID" && -n "$FETCH_SERIAL" ]]
}

# --- Non-root Workload API ------------------------------------------------------

# run_as_nonroot executes a command as NONROOT_USER. runuser(1) is preferred
# because it needs no shell on the account; su is the fallback for a guest that
# does not ship util-linux's runuser.
run_as_nonroot() {
	if [[ -n "$RUNUSER_BIN" ]]; then
		"$RUNUSER_BIN" -u "$NONROOT_USER" -- "$@"
		return $?
	fi
	local quoted="" arg
	for arg in "$@"; do
		quoted+=" $(printf '%q' "$arg")"
	done
	su -s /bin/sh -c "$quoted" -- "$NONROOT_USER"
}

# ensure_nonroot_user resolves NONROOT_USER, creating a system account if the
# guest does not already have one. No home, no shell: it exists to own a uid.
ensure_nonroot_user() {
	if id -u "$NONROOT_USER" >/dev/null 2>&1; then
		NONROOT_UID=$(id -u "$NONROOT_USER")
		log "nonroot: using existing user $NONROOT_USER uid=$NONROOT_UID"
		return 0
	fi

	if ! command -v useradd >/dev/null 2>&1; then
		log "RESULT check=issuance-nonroot outcome=ERROR reason=cannot_create_user user=$NONROOT_USER detail=useradd_missing"
		warn "$NONROOT_USER does not exist and useradd is not installed, so this run cannot prove that a"
		warn "non-root application reaches the Workload API. Create the account by hand, or set NONROOT_USER."
		return 1
	fi

	if ! useradd --system --no-create-home --shell /usr/sbin/nologin "$NONROOT_USER" >/dev/null 2>&1; then
		log "RESULT check=issuance-nonroot outcome=ERROR reason=cannot_create_user user=$NONROOT_USER detail=useradd_failed"
		warn "useradd $NONROOT_USER failed; this run cannot prove the non-root claim."
		return 1
	fi

	NONROOT_UID=$(id -u "$NONROOT_USER")
	log "nonroot: created system user $NONROOT_USER uid=$NONROOT_UID (no home, no shell)"
	return 0
}

# nonroot_socket_report prints the exposure the non-root path actually depends on:
# the mode of the socket and of the directory above it. Both are permitted
# evidence, and both are the first thing anyone reading a failure will want.
nonroot_socket_report() {
	local dir
	dir=$(dirname -- "$SOCKET_PATH")
	log "nonroot: socket=$SOCKET_PATH [$(stat -c '%A %U:%G' -- "$SOCKET_PATH" 2>/dev/null || printf '<absent>')] dir=$dir [$(stat -c '%A %U:%G' -- "$dir" 2>/dev/null || printf '<absent>')]"
}

# check_nonroot runs the standard Workload API client as an unprivileged user and
# sets NONROOT_VERDICT to PASS, FAIL or ERROR. It never dies: the caller decides
# what an unproven non-root claim does to the run, after rotation has been
# observed, so one run yields all the evidence it can.
check_nonroot() {
	local expected="${NONROOT_EXPECTED_SPIFFE_ID:-$EXPECTED_SPIFFE_ID}"
	NONROOT_VERDICT="ERROR"

	if [[ "$SELF_UID" != "0" ]]; then
		# This script is already unprivileged, so the fetch above WAS the non-root
		# case. Nothing to switch to.
		NONROOT_UID="$SELF_UID"
		NONROOT_ID="$FETCH_ID"
		NONROOT_SERIAL="$FIRST_SERIAL"
		NONROOT_VERDICT="PASS"
		log "RESULT check=issuance-nonroot outcome=PASS reason=primary_fetch_was_already_nonroot uid=$SELF_UID spiffe_id=$NONROOT_ID serial=$NONROOT_SERIAL socket=$SOCKET_PATH"
		return 0
	fi

	nonroot_socket_report
	ensure_nonroot_user || return 0

	# Traverse-only on the work mount: the root-owned fetch directories under it
	# stay 0700, so the unprivileged user can reach its own subdirectory and
	# nothing else.
	chmod o+x -- "$WORK_MOUNT" 2>/dev/null || true

	local dir="$WORK_DIR/nonroot"
	rm -rf -- "$dir"
	mkdir -p -- "$dir"
	chown "$NONROOT_USER" -- "$dir" || {
		log "RESULT check=issuance-nonroot outcome=ERROR reason=cannot_prepare_workdir user=$NONROOT_USER uid=$NONROOT_UID"
		return 0
	}
	chmod 0700 -- "$dir"

	if ! run_as_nonroot test -r "$SOCKET_PATH" || ! run_as_nonroot test -w "$SOCKET_PATH"; then
		log "RESULT check=issuance-nonroot outcome=ERROR reason=socket_unreachable_by_nonroot user=$NONROOT_USER uid=$NONROOT_UID socket=$SOCKET_PATH"
		warn "uid $NONROOT_UID cannot open $SOCKET_PATH, so an ordinary in-guest application cannot use"
		warn "this Workload API. SPIRE serves the socket 0777; the block is a directory above it. Fix the"
		warn "socket directory mode (guest-agent-bootstrap.sh creates it 0755) or move AGENT_SOCKET_PATH."
		return 0
	fi

	local rc=0
	run_as_nonroot "$SPIRE_AGENT_BIN" api fetch x509 \
		-socketPath "$SOCKET_PATH" \
		-timeout "$FETCH_TIMEOUT" \
		-write "$dir" >"$dir/fetch.out" 2>&1 || rc=$?
	safe_print "fetch[nonroot]" "$dir/fetch.out"

	local svid="$dir/svid.0.pem"
	if ((rc == 0)) && [[ -s "$svid" ]]; then
		NONROOT_ID=$(spiffe_id_of_leaf "$svid" || printf '')
		NONROOT_SERIAL=$("$OPENSSL_BIN" x509 -in "$svid" -noout -serial 2>/dev/null | cut -d= -f2)
		find "$dir" -name '*.key' -type f -exec shred -u -z -n 1 -- {} + 2>/dev/null || true
		log "svid[nonroot]: uid=$NONROOT_UID spiffe_id=${NONROOT_ID:-<absent>} serial=${NONROOT_SERIAL:--} key=<overwritten, never printed>"
		if [[ -n "$NONROOT_ID" && "$NONROOT_ID" == "$expected" ]]; then
			NONROOT_VERDICT="PASS"
			log "RESULT check=issuance-nonroot outcome=PASS user=$NONROOT_USER uid=$NONROOT_UID spiffe_id=$NONROOT_ID serial=$NONROOT_SERIAL socket=$SOCKET_PATH"
			return 0
		fi
		NONROOT_VERDICT="FAIL"
		log "RESULT check=issuance-nonroot outcome=FAIL reason=unexpected_spiffe_id user=$NONROOT_USER uid=$NONROOT_UID observed=${NONROOT_ID:-<absent>} expected=$expected"
		return 0
	fi

	find "$dir" -name '*.key' -type f -exec shred -u -z -n 1 -- {} + 2>/dev/null || true

	if grep -qiE 'permission denied|connection refused|no such file or directory|cannot connect|unavailable' -- "$dir/fetch.out" 2>/dev/null &&
		! grep -qiE 'no identity issued|no such registration' -- "$dir/fetch.out" 2>/dev/null; then
		log "RESULT check=issuance-nonroot outcome=ERROR reason=socket_unreachable_by_nonroot user=$NONROOT_USER uid=$NONROOT_UID socket=$SOCKET_PATH fetch_rc=$rc"
		warn "the non-root fetch could not talk to $SOCKET_PATH at all: an ordinary application cannot use"
		warn "this Workload API as configured."
		return 0
	fi

	if grep -qiE 'no identity issued|no such registration|PermissionDenied' -- "$dir/fetch.out" 2>/dev/null; then
		log "RESULT check=issuance-nonroot outcome=ERROR reason=no_entry_for_nonroot_uid user=$NONROOT_USER uid=$NONROOT_UID expected=$expected fetch_rc=$rc socket_reachable=yes"
		warn "the Workload API ANSWERED uid $NONROOT_UID but issued nothing: reachability is proven, issuance"
		warn "is not, because no registration entry's unix selectors match that uid. Register one and re-run:"
		warn "  spire-server entry create -parentID <this guest's node SPIFFE ID> \\"
		warn "    -spiffeID $expected -selector unix:uid:$NONROOT_UID -x509SVIDTTL 120"
		return 0
	fi

	log "RESULT check=issuance-nonroot outcome=ERROR reason=nonroot_fetch_failed user=$NONROOT_USER uid=$NONROOT_UID fetch_rc=$rc"
	warn "the non-root fetch failed for a reason this harness cannot classify; see fetch[nonroot] above."
	return 0
}

# --- Rotation -----------------------------------------------------------------

# rotation_by_polling waits for the point where SPIRE rotates an X509-SVID — half
# of its lifetime, per the agent's default rotation strategy — and fetches again.
# The wait is derived from the certificate itself rather than from an assumption
# about the entry's TTL.
rotation_by_polling() {
	local not_before_epoch not_after_epoch now lifetime renew_at target floor wait
	not_before_epoch=$(epoch_of "$FETCH_NOT_BEFORE")
	not_after_epoch=$(epoch_of "$FETCH_NOT_AFTER")
	now=$(date -u +%s)

	if [[ -z "$not_before_epoch" || -z "$not_after_epoch" ]]; then
		log "RESULT check=rotation outcome=ERROR reason=unparseable_validity not_before=${FETCH_NOT_BEFORE:--} not_after=${FETCH_NOT_AFTER:--}"
		die 22 "cannot parse the SVID validity window, so the renewal point cannot be derived"
	fi

	lifetime=$((not_after_epoch - not_before_epoch))
	renew_at=$((not_before_epoch + lifetime / 2))
	target=$((renew_at + ROTATION_GRACE_SECONDS))

	# The agent rotates on its own schedule, so the fetch immediately after the
	# renewal point can legitimately still serve the cached SVID. Observe for at
	# least ROTATION_MIN_WAIT_SECONDS past now before concluding that nothing
	# rotated; otherwise a certificate whose renewal point has already passed would
	# be judged by a single extra fetch with no patience at all.
	floor=$((now + ROTATION_MIN_WAIT_SECONDS))
	if ((target < floor)); then
		target=$floor
	fi

	wait=$((target - now))
	((wait < 0)) && wait=0

	log "rotation: svid_lifetime_seconds=$lifetime renewal_point_in=$((renew_at - now))s wait_seconds=$wait grace=${ROTATION_GRACE_SECONDS}s min_observation=${ROTATION_MIN_WAIT_SECONDS}s poll_interval=${ROTATION_POLL_INTERVAL}s"

	if ((wait > ROTATION_MAX_WAIT_SECONDS)); then
		log "RESULT check=rotation outcome=ERROR reason=window_exceeds_cap wait_seconds=$wait cap_seconds=$ROTATION_MAX_WAIT_SECONDS svid_lifetime_seconds=$lifetime"
		die 22 "rotation would need ${wait}s, more than ROTATION_MAX_WAIT_SECONDS=$ROTATION_MAX_WAIT_SECONDS. Shorten the registration entry's x509SVIDTTL for this case, or raise the cap deliberately."
	fi

	local started
	started=$(date -u +%s)
	while :; do
		now=$(date -u +%s)
		if ((now >= target)); then
			break
		fi
		sleep "$((ROTATION_POLL_INTERVAL < target - now ? ROTATION_POLL_INTERVAL : target - now))"
		if ! fetch_svid "poll"; then
			log "RESULT check=rotation outcome=ERROR reason=workload_api_unavailable_during_wait"
			die 10 "the Workload API stopped answering while waiting for a rotation"
		fi
		if [[ "$FETCH_SERIAL" != "$FIRST_SERIAL" ]]; then
			SECOND_SERIAL="$FETCH_SERIAL"
			log "RESULT check=rotation outcome=PASS mode=poll first_serial=$FIRST_SERIAL second_serial=$SECOND_SERIAL waited_seconds=$(($(date -u +%s) - started)) spiffe_id=$FETCH_ID"
			return 0
		fi
	done

	if ! fetch_svid "final"; then
		log "RESULT check=rotation outcome=ERROR reason=workload_api_unavailable_at_deadline"
		die 10 "the Workload API stopped answering at the rotation deadline"
	fi
	SECOND_SERIAL="$FETCH_SERIAL"

	if [[ "$SECOND_SERIAL" != "$FIRST_SERIAL" ]]; then
		log "RESULT check=rotation outcome=PASS mode=poll first_serial=$FIRST_SERIAL second_serial=$SECOND_SERIAL waited_seconds=$(($(date -u +%s) - started)) spiffe_id=$FETCH_ID"
		return 0
	fi

	log "RESULT check=rotation outcome=FAIL mode=poll first_serial=$FIRST_SERIAL second_serial=$SECOND_SERIAL waited_seconds=$(($(date -u +%s) - started)) reason=serial_unchanged_after_renewal_point"
	die 21 "the SVID serial did not change after the renewal point plus ${ROTATION_GRACE_SECONDS}s grace and at least ${ROTATION_MIN_WAIT_SECONDS}s of polling: the agent is not rotating"
}

# rotation_by_watching uses the streaming Workload API. `api watch` has no timeout
# flag, so the bound comes from timeout(1). It proves an update arrived but cannot
# report serials, which is why poll is the default.
rotation_by_watching() {
	require_tool timeout timeout PATH

	local seconds="$ROTATION_MAX_WAIT_SECONDS"
	local out="$WORK_DIR/watch.out"
	log "rotation: watching $SOCKET_PATH for ${seconds}s (mode=watch; serials are not observable this way)"

	timeout "$seconds" "$SPIRE_AGENT_BIN" api watch -socketPath "$SOCKET_PATH" >"$out" 2>&1 || true
	safe_print "watch" "$out"

	local updates
	updates=$(grep -c -E 'Received [0-9]+ svid' "$out" 2>/dev/null || true)
	updates="${updates:-0}"
	local ids
	ids=$(grep -o 'spiffe://[^[:space:]]*' "$out" 2>/dev/null | sort -u | tr '\n' ',' || printf '')

	if ((updates >= 2)); then
		log "RESULT check=rotation outcome=PASS mode=watch updates=$updates spiffe_ids=${ids%,} serials=unavailable_in_watch_mode waited_seconds=$seconds"
		return 0
	fi

	log "RESULT check=rotation outcome=FAIL mode=watch updates=$updates spiffe_ids=${ids%,} waited_seconds=$seconds reason=no_second_update"
	die 21 "only $updates Workload API update(s) arrived in ${seconds}s: no rotation was observed"
}

# --- Main ---------------------------------------------------------------------

usage() {
	cat <<'EOF'
usage: guest-workload-check.sh [EXPECTED_SPIFFE_ID]

Runs inside a spike guest once its local spire-agent is attested. The expected
SPIFFE ID is the first positional argument or EXPECTED_SPIFFE_ID.

  SOCKET_PATH                 default /tmp/spire-agent/public/api.sock
  SPIRE_AGENT_BIN             default spire-agent
  FETCH_TIMEOUT               default 10s (passed to api fetch -timeout)
  ROTATION_MODE               poll (default) | watch | skip
  ROTATION_MAX_WAIT_SECONDS   default 900
  ROTATION_POLL_INTERVAL      default 15
  ROTATION_GRACE_SECONDS      default 30
  ROTATION_MIN_WAIT_SECONDS   default 45 (minimum polling past the renewal point)
  WORK_MOUNT                  default /run/spike-workload-check (mounted tmpfs)
  WORK_TMPFS_SIZE             default 1m
  ALLOW_NON_TMPFS_WORKDIR     1 permits a disk-backed work directory
  OPENSSL_BIN                 default openssl
  NONROOT_CHECK               run (default) | skip — fetch again as an
                              unprivileged user, which is the phase's real claim
  NONROOT_USER                default spike-workload (created if absent)
  NONROOT_EXPECTED_SPIFFE_ID  SPIFFE ID the non-root caller must receive;
                              defaults to the root one, which only matches if the
                              entry's unix selectors cover that uid

Prints SPIFFE IDs, validity windows, serials and counts. Never key material.
EOF
}

main() {
	if (($# > 0)); then
		case "$1" in
		-h | --help)
			usage
			exit 0
			;;
		-*) die 2 "unexpected option: $1 (try --help)" ;;
		*)
			EXPECTED_SPIFFE_ID="$1"
			shift
			;;
		esac
	fi
	(($# == 0)) || die 2 "unexpected argument: $1 (try --help)"

	[[ -n "$EXPECTED_SPIFFE_ID" ]] ||
		die 2 "an expected SPIFFE ID is required: pass it as the first argument or set EXPECTED_SPIFFE_ID. Without it this script can report an SVID but cannot decide anything."
	[[ "$EXPECTED_SPIFFE_ID" == spiffe://* ]] ||
		die 2 "the expected SPIFFE ID must start with spiffe://, got: $EXPECTED_SPIFFE_ID"

	case "$ROTATION_MODE" in
	poll | watch | skip) ;;
	*) die 2 "ROTATION_MODE must be poll, watch or skip, got: $ROTATION_MODE" ;;
	esac
	case "$NONROOT_CHECK" in
	run | skip) ;;
	*) die 2 "NONROOT_CHECK must be run or skip, got: $NONROOT_CHECK" ;;
	esac

	require_tool "$SPIRE_AGENT_BIN" "the guest SPIRE agent" SPIRE_AGENT_BIN
	require_tool "$OPENSSL_BIN" openssl OPENSSL_BIN
	require_tool mount mount PATH
	require_tool umount umount PATH
	require_tool shred shred PATH
	require_tool find find PATH
	require_tool stat stat PATH
	require_tool date date PATH

	SELF_UID=$(id -u)
	# The primary fetch is labelled by what it actually is. It is normally root,
	# because the harness mounts a tmpfs, but a run started by an ordinary user is
	# itself the non-root evidence and must not be mislabelled.
	CALLER_LABEL=root
	[[ "$SELF_UID" == "0" ]] || CALLER_LABEL=nonroot
	if [[ "$SELF_UID" != "0" ]]; then
		warn "not running as root (uid $SELF_UID): the tmpfs mount and $SOCKET_PATH may be inaccessible,"
		warn "and the non-root check below reports this process instead of switching users."
	elif [[ "$NONROOT_CHECK" == "run" ]]; then
		if command -v runuser >/dev/null 2>&1; then
			RUNUSER_BIN=runuser
		elif ! command -v su >/dev/null 2>&1; then
			log "RESULT check=issuance-nonroot outcome=ERROR reason=missing_dependency dependency=runuser_or_su"
			die 6 "neither runuser nor su is installed, so this run cannot fetch as an unprivileged user (set NONROOT_CHECK=skip to opt out and record an incomplete run)"
		fi
	fi
	[[ -S "$SOCKET_PATH" ]] || warn "$SOCKET_PATH is not a socket yet; the fetch below will say whether the agent is serving"

	trap on_exit EXIT
	mount_work_tmpfs

	local health="$WORK_DIR/health.out"
	if "$SPIRE_AGENT_BIN" healthcheck -socketPath "$SOCKET_PATH" -verbose >"$health" 2>&1; then
		safe_print "health" "$health"
	else
		safe_print "health" "$health"
		warn "the agent healthcheck did not pass; the fetch below decides the outcome"
	fi

	if ! fetch_svid "first"; then
		log "RESULT check=issuance outcome=ERROR reason=workload_api_no_svid socket=$SOCKET_PATH"
		log "RESULT check=workload outcome=ERROR reason=workload_api_no_svid socket=$SOCKET_PATH"
		die 10 "the Workload API at $SOCKET_PATH returned no usable SVID (is the agent attested, and is there a registration entry whose unix selectors match this caller?)"
	fi
	FIRST_SERIAL="$FETCH_SERIAL"

	log "issuance: expected_spiffe_id=$EXPECTED_SPIFFE_ID caller=$CALLER_LABEL uid=$SELF_UID"
	if [[ "$FETCH_ID" != "$EXPECTED_SPIFFE_ID" ]]; then
		log "RESULT check=issuance outcome=FAIL caller=$CALLER_LABEL uid=$SELF_UID observed=$FETCH_ID expected=$EXPECTED_SPIFFE_ID serial=$FIRST_SERIAL"
		log "RESULT check=workload outcome=FAIL reason=unexpected_spiffe_id observed=$FETCH_ID expected=$EXPECTED_SPIFFE_ID"
		die 20 "the Workload API issued $FETCH_ID, not $EXPECTED_SPIFFE_ID"
	fi
	log "RESULT check=issuance outcome=PASS caller=$CALLER_LABEL uid=$SELF_UID spiffe_id=$FETCH_ID serial=$FIRST_SERIAL not_before=$FETCH_NOT_BEFORE not_after=$FETCH_NOT_AFTER"

	# The non-root case is a SEPARATE verdict, taken before the rotation wait so
	# one run yields both, and judged at the end so a failure here cannot hide
	# behind the root result.
	if [[ "$NONROOT_CHECK" == "skip" ]]; then
		NONROOT_VERDICT="SKIPPED"
		warn "NONROOT_CHECK=skip: this run proves only that ROOT can use the Workload API. P9's acceptance"
		warn "is an in-guest APPLICATION, so this run is NOT complete evidence for the phase."
		log "RESULT check=issuance-nonroot outcome=SKIPPED reason=nonroot_check_skip"
	else
		check_nonroot
	fi

	local rotation="skipped"
	case "$ROTATION_MODE" in
	poll)
		rotation_by_polling
		rotation="observed"
		;;
	watch)
		rotation_by_watching
		rotation="observed"
		;;
	skip)
		warn "ROTATION_MODE=skip: issuance was checked and rotation was not. P9 step 3 requires rotation,"
		warn "so this run is NOT complete evidence for the phase."
		log "RESULT check=rotation outcome=SKIPPED reason=rotation_mode_skip"
		;;
	esac

	# A rotation must not change who the workload is.
	if [[ "$rotation" == "observed" && -n "$FETCH_ID" && "$FETCH_ID" != "$EXPECTED_SPIFFE_ID" ]]; then
		log "RESULT check=workload outcome=FAIL reason=identity_changed_across_rotation observed=$FETCH_ID expected=$EXPECTED_SPIFFE_ID"
		die 20 "after rotation the Workload API issued $FETCH_ID, not $EXPECTED_SPIFFE_ID"
	fi

	if [[ "$NONROOT_VERDICT" != "PASS" && "$NONROOT_VERDICT" != "SKIPPED" ]]; then
		log "RESULT check=workload outcome=ERROR reason=nonroot_workload_api_unproven nonroot=$NONROOT_VERDICT root=PASS spiffe_id=$EXPECTED_SPIFFE_ID socket=$SOCKET_PATH rotation=$rotation"
		die 24 "root obtained $EXPECTED_SPIFFE_ID but a non-root caller did not (see the issuance-nonroot RESULT line): the phase's claim is that an in-guest APPLICATION is served, and that is unproven"
	fi

	if ! reclaim_workdir; then
		log "RESULT check=workload outcome=ERROR reason=workdir_not_reclaimed material=live"
		exit 8
	fi

	log "RESULT check=workload outcome=PASS spiffe_id=$EXPECTED_SPIFFE_ID socket=$SOCKET_PATH first_serial=$FIRST_SERIAL second_serial=${SECOND_SERIAL:--} rotation=$rotation mode=$ROTATION_MODE nonroot=$NONROOT_VERDICT nonroot_uid=${NONROOT_UID:--} material=$RECLAIMED"
}

main "$@"

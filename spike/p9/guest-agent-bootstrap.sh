#!/usr/bin/env bash
#
# guest-agent-bootstrap.sh — P9 in-guest bootstrap. Runs as root INSIDE a spike
# guest, reads the instance's one-time nonce from its own /dev/incus/sock,
# redeems it for a broker-obtained EXCHANGE SVID, hands that credential to a
# guest-local spire-agent via NodeAttestor "x509pop", waits for the agent to
# attest, reports the node SPIFFE ID it obtained, and then destroys the exchange
# material.
#
# THROWAWAY spike tooling. Appendix C of SPIKE_PLAN.md classifies everything
# under spike/ as never merged as product code: it is deletable without loss,
# because the evidence it produces lives in the journal. Do not import, wrap, or
# promote any of this. The durable counterparts are cmd/incus-spiffe-broker,
# internal/broker, internal/nonce, and internal/incus/bootstrap.
#
# ---------------------------------------------------------------------------
# WHY THE EXCHANGE SVID IS TRUSTWORTHY
# ---------------------------------------------------------------------------
# Nothing this script does establishes the guest's identity. The exchange SVID
# exists only because the physically attested HOST agent's incus-attestor plugin
# independently derived incus:uuid:<uuid> from the authoritative Incus instance
# record, and the SPIRE server matched a registration entry keyed on that
# selector. This guest merely proves possession of a single-use nonce that the
# broker wrote into its own instance configuration. The trust root is the host
# TPM, not this script.
#
#   exchange SVID  spiffe://<trust_domain>/spire-exchange/incus/<instance-uuid>
#   node SVID      spiffe://<trust_domain>/spire/agent/x509pop/incus/<instance-uuid>
#
# The second form is what the server's x509pop plugin derives from the first
# with mode = "spiffe" and the documented v1.15.2 defaults
# svid_prefix = "/spire-exchange" and
# agent_path_template = "{{ .PluginName }}/{{ .SVIDPathTrimmed }}" (P2 evidence).
#
# ---------------------------------------------------------------------------
# SECRET HANDLING — Appendix D rules 1 and 5, and now a PRIVATE KEY
# ---------------------------------------------------------------------------
# P8 had one secret in play, the nonce. P9 adds a second and worse one: the
# redeem RESPONSE BODY now carries the exchange private key. So:
#
#   * No code path prints the nonce value, the exchange private key, or any
#     response body. Named, non-secret fields only: nonce IDs, payload digests,
#     certificate fingerprints, serials, SPIFFE IDs, validity windows, selectors,
#     HTTP status codes. Appendix D rule 3 permits exactly those.
#   * The nonce never reaches argv (world-readable through /proc): the request
#     body is built by jq from jq's own stdin and piped to curl on stdin, and
#     grep patterns are read from a file.
#   * The response body and every file derived from it are written ONLY into a
#     tmpfs this script mounts itself, mode 0700 directory, mode 0600 files. The
#     key is never assigned to a shell variable — it is moved from jq's stdout
#     straight into a file.
#   * A transcript of this script is safe to paste into evidence. A transcript of
#     curl -v against the redeem endpoint is NOT: it would capture the key.
#
# ---------------------------------------------------------------------------
# EXCHANGE-KEY HANDLING — a KNOWN-UNSOLVED design point, not a solved one
# ---------------------------------------------------------------------------
# SPIKE_PLAN.md P9 step 2 requires this spike to RECORD how the exchange key is
# delivered and held rather than to declare the problem solved (risk R7,
# "exchange-credential delivery to guest exposes key material", is an explicit
# pre-production hardening item in the go/no-go). The stance implemented here:
#
#   memory-only   the key exists on a tmpfs this script mounts, never on a
#                 persistent guest filesystem, so it cannot survive a power cut
#                 and cannot be recovered from a disk image or a snapshot;
#   single-use    it is used for exactly one x509pop attestation;
#   short-lived   it is shredded and its tmpfs unmounted the moment attestation
#                 succeeds, so it does not outlive its use.
#
# What that does NOT prove: tmpfs pages can be swapped, a memory dump or a
# hypervisor-side read of guest RAM sees the key while it is live, and shred(1)
# on tmpfs is an overwrite of pages plus an unlink, not cryptographic erasure —
# Appendix D rule 2 forbids claiming erasure that has not been demonstrated. The
# honest claim is scope reduction: memory-only, single-use, short-lived.
#
# ---------------------------------------------------------------------------
# EXIT CODES (the P9 live run judges on these plus the final RESULT line)
# ---------------------------------------------------------------------------
#   0   PASS: attested, node SPIFFE ID as expected, exchange material destroyed
#   2   usage: an unexpected argument, a missing required variable, a bad value
#   3   guest socket read failed (key absent, forbidden, or socket missing)
#   4   malformed payload, or malformed/missing exchange material in the response
#       (not PEM, unparseable key, or a key that does not match the certificate)
#   5   TLS pin failure: the broker certificate does not match the fingerprint
#       carried in the payload. The nonce is NOT sent
#   6   a required binary is missing inside the guest
#   7   no memory-backed directory could be established. Nothing is requested and
#       the nonce is NOT sent: this script refuses to put an exchange key on a
#       persistent guest filesystem
#   8   the exchange material could not be shredded and unmounted. It supersedes
#       every other code, including 0: a live key that outlived its use is the
#       most urgent fact of the run
#   10  broker answered 401 (unknown nonce ID or wrong secret)
#   11  broker answered 409 (nonce exists, state forbids redemption)
#   12  broker answered 500 (broker internal error)
#   13  broker answered 503 (broker dependency unavailable)
#   14  broker answered some other non-2xx status, or the response echoed a secret
#   15  redeem transport failure: no HTTP status was obtained
#   20  the agent did not attest, or did not become ready, within
#       AGENT_READY_TIMEOUT — ERROR, no decision was observed
#   21  the agent attested but the node SPIFFE ID is not the expected form — FAIL
#   23  the delivered exchange SVID's SPIFFE ID is not the expected form — FAIL,
#       and the agent is not started, because the node path would be wrong

set -euo pipefail
umask 077

# --- Parameters ---------------------------------------------------------------

CURL_BIN="${CURL_BIN:-curl}"
JQ_BIN="${JQ_BIN:-jq}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
SPIRE_AGENT_BIN="${SPIRE_AGENT_BIN:-spire-agent}"

# Guest API. Identical for containers and VMs per evidence/p8/GUEST_SOCK_BRIEF.md:
# GET /1.0/config/user.spiffe-bootstrap returns the raw configured string with
# Content-Type application/octet-stream, no JSON envelope, no trailing newline.
# Only user.*/cloud-init.* keys are visible, so a guest cannot read volatile.uuid
# and cannot prove its own identity; the broker resolves the binding server-side.
GUEST_SOCKET="${GUEST_SOCKET:-/dev/incus/sock}"
BOOTSTRAP_KEY="${BOOTSTRAP_KEY:-user.spiffe-bootstrap}"
PAYLOAD_FILE="${PAYLOAD_FILE:-}"

# Broker endpoint. The payload's broker_url is authoritative; the override exists
# for split-horizon DNS on the spike bridge.
BROKER_URL_OVERRIDE="${BROKER_URL_OVERRIDE:-}"
REDEEM_PATH="${REDEEM_PATH:-/v1alpha1/redeem}"
BROKER_CACERT="${BROKER_CACERT:-}"
BROKER_TLS_HOSTNAME="${BROKER_TLS_HOSTNAME:-}"
ALLOW_INSECURE_TLS="${ALLOW_INSECURE_TLS:-0}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-30}"

# Identity shapes. The prefixes are variables because P9's own acceptance is that
# the v1.15.2 defaults produce them; a template change is configuration, not
# architecture (SPIKE_PLAN.md P9 failure interpretation).
TRUST_DOMAIN="${TRUST_DOMAIN:-spike.incus.internal}"
EXCHANGE_ID_PREFIX="${EXCHANGE_ID_PREFIX:-/spire-exchange/incus}"
NODE_ID_PREFIX="${NODE_ID_PREFIX:-/spire/agent/x509pop/incus}"
ALLOW_UNEXPECTED_EXCHANGE_ID="${ALLOW_UNEXPECTED_EXCHANGE_ID:-0}"

# The exchange material directory. Mounted by this script as tmpfs; never a path
# on a persistent guest filesystem.
EXCHANGE_DIR="${EXCHANGE_DIR:-/run/spike-exchange}"
EXCHANGE_TMPFS_SIZE="${EXCHANGE_TMPFS_SIZE:-1m}"
KEEP_EXCHANGE_MATERIAL="${KEEP_EXCHANGE_MATERIAL:-0}"

# Agent configuration inputs. SPIRE_SERVER_ADDRESS has no default on purpose: a
# wrong guess is indistinguishable from a broken attestation and would be
# reported as exit 20 minutes later.
SPIRE_SERVER_ADDRESS="${SPIRE_SERVER_ADDRESS:-}"
SPIRE_SERVER_PORT="${SPIRE_SERVER_PORT:-8081}"
AGENT_CONF_TEMPLATE="${AGENT_CONF_TEMPLATE:-}"
AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/spike-p9}"
AGENT_DATA_DIR="${AGENT_DATA_DIR:-/var/lib/spire-agent}"
AGENT_SOCKET_PATH="${AGENT_SOCKET_PATH:-/tmp/spire-agent/public/api.sock}"
AGENT_LOG_LEVEL="${AGENT_LOG_LEVEL:-DEBUG}"
AGENT_KEY_MANAGER="${AGENT_KEY_MANAGER:-memory}"
AGENT_HEALTH_BIND_ADDRESS="${AGENT_HEALTH_BIND_ADDRESS:-localhost}"
AGENT_HEALTH_BIND_PORT="${AGENT_HEALTH_BIND_PORT:-8080}"
AGENT_START_MODE="${AGENT_START_MODE:-background}"
AGENT_UNIT="${AGENT_UNIT:-spike-spire-agent}"
AGENT_READY_TIMEOUT="${AGENT_READY_TIMEOUT:-90}"

# The trust bundle is PUBLIC material (Appendix D rule 3). Persisting it is what
# lets the agent be restarted without a new bootstrap; the private key is never
# persisted either way. With 0, nothing at all survives the tmpfs unmount and the
# agent cannot even start again, because trust_bundle_path would not exist.
PERSIST_TRUST_BUNDLE="${PERSIST_TRUST_BUNDLE:-1}"

# Explicit jq filter overrides for the exchange material, so a field-naming
# difference in the broker's redeem body never blocks a live run.
CHAIN_JQ="${CHAIN_JQ:-}"
KEY_JQ="${KEY_JQ:-}"
BUNDLE_JQ="${BUNDLE_JQ:-}"

readonly SOCKET_URL_BASE='http://localhost/1.0/config'

# --- State --------------------------------------------------------------------

NONCE_ID="-"
SECRET_FILE=""
STATUS_EXIT=14
PINNED_LEAF=""
PINNED_SPKI=""
WORK_DIR=""
MOUNTED=0
TRAP_DONE=0
RECLAIMED="not-attempted"
AGENT_PID=""
AGENT_LOG=""
INSTANCE_UUID="-"
EXCHANGE_ID="-"
EXCHANGE_NOT_AFTER="-"
NODE_ID="-"

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

# require_tool exits 6, not 2, when a binary is absent: a missing dependency means
# the phase never ran, and the live run must record ERROR rather than invent a
# security verdict. The same fact appears on a RESULT line.
require_tool() {
	command -v "$1" >/dev/null 2>&1 && return 0
	log "RESULT phase=p9-bootstrap outcome=ERROR reason=missing_dependency dependency=$1"
	die 6 "$2 not found inside this guest: $1 (install it, or override with $3)"
}

is_ip_literal() {
	[[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ || "$1" == *:* ]]
}

# is_mounted reads /proc/self/mounts rather than shelling out to mountpoint(1),
# which is not present in every minimal guest.
is_mounted() {
	awk -v d="$1" '$2 == d { hit = 1 } END { exit hit ? 0 : 1 }' /proc/self/mounts
}

normalize_fingerprint() {
	printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d ': \t\n' | sed -e 's/^sha256//'
}

sha256_stdin() {
	"$OPENSSL_BIN" dgst -sha256 | awk '{print $NF}'
}

# body_leaks_secret reports whether a file contains the nonce value. The pattern
# comes from SECRET_FILE, a 0600 file in the tmpfs, so the secret never reaches
# grep's argv and never occupies a shell variable.
body_leaks_secret() {
	local file="$1"
	[[ -n "$SECRET_FILE" && -s "$SECRET_FILE" ]] || return 1
	grep -q -F -f "$SECRET_FILE" -- "$file"
}

# json_field prints the first non-empty value among the supplied top-level field
# names. One canonical spelling per field plus the obvious alternate: a spike
# broker's field naming is not a frozen contract, and a live run must not die
# over cosmetics.
json_field() {
	local file="$1"
	shift
	local names=("$@") filter="" name
	for name in "${names[@]}"; do
		filter+="${filter:+, }.\"${name}\"?"
	done
	"$JQ_BIN" -r "first((${filter}) | select(. != null and . != \"\")) // \"\"" <"$file" 2>/dev/null || printf ''
}

# safe_stream prefixes another program's output without becoming a leak path: a
# line carrying a PEM private-key header, or a long line that is nothing but
# base64, is withheld. The base64 test is a length comparison plus an anchored
# character class rather than an {n,} interval, because mawk — the default awk on
# Debian, which is what the guests run — matches an open-ended interval against
# every line, and a filter that withholds everything is not a filter.
safe_stream() {
	awk -v p="$1" '
		/PRIVATE KEY/ { print p ": <line withheld: possible key material>"; next }
		length($0) >= 64 && $0 ~ /^[[:space:]]*[A-Za-z0-9+\/=]+[[:space:]]*$/ {
			print p ": <line withheld: possible key material>"; next
		}
		{ print p ": " $0 }
	'
}

safe_print() {
	local prefix="$1" file="$2"
	[[ -s "$file" ]] || return 0
	safe_stream "$prefix" <"$file"
}

# build_material_filter builds a jq filter that looks for each candidate field
# name at the top level and inside the obvious wrapper objects, and yields the
# first non-empty string. Used for PEM material, whose value must never pass
# through a shell variable, so the filter's output is redirected straight to a
# file.
build_material_filter() {
	local out="" name container
	for name in "$@"; do
		for container in '.' '.exchange_svid' '.svid' '.exchange'; do
			out+="${out:+, }${container}[\"${name}\"]?"
		done
	done
	printf 'first((%s) | select(type == "string" and . != "")) // ""' "$out"
}

# extract_pem writes one PEM blob from the response into its own 0600 file inside
# the tmpfs. The bytes go from jq's stdout to the file: no variable, no argv, no
# log line. Returns non-zero when nothing was found.
extract_pem() {
	local response="$1" out="$2" override="$3"
	shift 3
	local filter
	if [[ -n "$override" ]]; then
		filter="$override"
	else
		filter=$(build_material_filter "$@")
	fi
	"$JQ_BIN" -r "$filter" <"$response" >"$out" 2>/dev/null || :
	[[ -s "$out" ]] && grep -q -- '-----BEGIN' "$out"
}

# spiffe_id_of_leaf prints the URI SAN of the first certificate in a PEM file.
# openssl x509 reads only the leading certificate, which is the leaf by contract.
spiffe_id_of_leaf() {
	local pem="$1" found
	found=$("$OPENSSL_BIN" x509 -in "$pem" -noout -text 2>/dev/null |
		grep -o 'URI:spiffe://[^,[:space:]]*' | head -n 1) || return 1
	printf '%s' "${found#URI:}"
}

# --- Memory-backed storage ----------------------------------------------------

# mount_exchange_tmpfs establishes the only place this script is willing to put
# exchange material. It refuses to continue on anything that is not tmpfs, which
# is why the nonce has not been sent yet at this point: a run that cannot hold the
# key in memory must not request one.
mount_exchange_tmpfs() {
	local dir="$EXCHANGE_DIR"

	if is_mounted "$dir"; then
		local existing
		existing=$(stat -f -c %T -- "$dir" 2>/dev/null || printf 'unknown')
		if [[ "$existing" != "tmpfs" ]]; then
			log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_dir_not_tmpfs fstype=$existing"
			die 7 "$dir is already a $existing mount; refusing to place exchange material on it"
		fi
		warn "$dir is already a tmpfs mount from an earlier run: reusing it after shredding its contents"
		reclaim_files "$dir"
		MOUNTED=1
	else
		mkdir -p -- "$dir" || die 7 "cannot create $dir"
		chmod 0700 -- "$dir" || die 7 "cannot chmod 0700 $dir"
		if ! mount -t tmpfs -o "size=$EXCHANGE_TMPFS_SIZE,mode=0700,nosuid,nodev,noexec" tmpfs "$dir" 2>/dev/null; then
			log "RESULT phase=p9-bootstrap outcome=ERROR reason=tmpfs_mount_failed dir=$dir"
			die 7 "cannot mount tmpfs at $dir; refusing to write an exchange key to a persistent filesystem"
		fi
		MOUNTED=1
	fi

	local fstype
	fstype=$(stat -f -c %T -- "$dir" 2>/dev/null || printf 'unknown')
	if [[ "$fstype" != "tmpfs" ]]; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_dir_not_tmpfs fstype=$fstype"
		die 7 "$dir is $fstype, not tmpfs, after mounting; refusing to continue"
	fi

	chmod 0700 -- "$dir"
	WORK_DIR="$dir/work"
	mkdir -p -- "$WORK_DIR"
	chmod 0700 -- "$WORK_DIR"
	log "exchange: $dir is tmpfs (size=$EXCHANGE_TMPFS_SIZE, mode 0700, nosuid,nodev,noexec), memory-backed"
}

# reclaim_files overwrites and unlinks every file under a directory. On tmpfs this
# is an overwrite of pages plus an unlink; Appendix D rule 2 forbids calling that
# cryptographic erasure, and this harness does not.
reclaim_files() {
	local dir="$1"
	[[ -d "$dir" ]] || return 0
	find "$dir" -type f -exec shred -u -z -n 1 -- {} + 2>/dev/null || true
	find "$dir" -mindepth 1 -delete 2>/dev/null || true
	return 0
}

# reclaim_exchange_material is the counterpart of mount_exchange_tmpfs: shred the
# files, then unmount, then VERIFY both. "We tried" is not the requirement; the
# requirement is that the exchange key does not outlive its single use.
#
# The running agent is unaffected: it read the certificate, the key and the bundle
# once, at attestation, and holds what it needs in memory and in its own data dir.
# It does not reopen these paths until it re-attests — which is exactly the
# re-attestation story this phase has to define, not discover: with the material
# gone, a restart needs a fresh nonce.
reclaim_exchange_material() {
	local dir="$EXCHANGE_DIR"

	if ((MOUNTED == 0)); then
		RECLAIMED="nothing-to-do"
		return 0
	fi

	reclaim_files "$dir"

	local failures=()
	if is_mounted "$dir"; then
		umount -- "$dir" 2>/dev/null || umount -l -- "$dir" 2>/dev/null || true
		if is_mounted "$dir"; then
			failures+=("still mounted: $dir")
		fi
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
			warn "exchange material was NOT reclaimed: $f"
		done
		warn "run this by hand now: find $dir -type f -exec shred -u -z -n 1 {} + && umount $dir"
		return 1
	fi

	MOUNTED=0
	RECLAIMED="shredded-and-unmounted"
	log "exchange: material shredded and $dir unmounted (memory-only, single-use, short-lived)"
	return 0
}

# on_exit reclaims on every path, including an abort, and lets a reclaim failure
# supersede the run's own status: a live exchange key is the more urgent fact.
on_exit() {
	local status=$?
	((TRAP_DONE)) && return
	TRAP_DONE=1

	if ((MOUNTED == 1)) && ((status != 0)) && [[ "$KEEP_EXCHANGE_MATERIAL" == "1" ]]; then
		RECLAIMED="kept-by-request"
		warn "KEEP_EXCHANGE_MATERIAL=1 and the run failed: the exchange key is LIVE in $EXCHANGE_DIR."
		warn "It is memory-backed and dies with the guest, but destroy it now unless you are debugging:"
		warn "  find $EXCHANGE_DIR -type f -exec shred -u -z -n 1 {} + && umount $EXCHANGE_DIR"
		exit "$status"
	fi

	if [[ "$AGENT_START_MODE" == "none" ]] && ((status == 0)); then
		exit "$status"
	fi

	if ! reclaim_exchange_material; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_material_not_reclaimed exchange_material=live exit_was=$status"
		exit 8
	fi

	exit "$status"
}

# --- Payload acquisition ------------------------------------------------------

# read_payload_to_file performs the guest read and leaves the raw configured
# string in $1. Those bytes carry the nonce; only jq ever reads them.
read_payload_to_file() {
	local out="$1" status rc
	set +e
	status=$("$CURL_BIN" --silent --show-error \
		--unix-socket "$GUEST_SOCKET" \
		--output "$out" \
		--write-out '%{http_code}' \
		"$SOCKET_URL_BASE/$BOOTSTRAP_KEY" 2>"$WORK_DIR/socket.err")
	rc=$?
	set -e

	if ((rc != 0)) || [[ -z "$status" ]]; then
		safe_print socket_read "$WORK_DIR/socket.err" >&2 || true
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=guest_socket_unreachable socket_status=000"
		die 3 "cannot reach $GUEST_SOCKET (container: security.guestapi must not be false; VM: incus-agent must be running; must run as guest root)"
	fi

	log "socket_read: GET /1.0/config/$BOOTSTRAP_KEY -> HTTP $status"

	case "$status" in
	200) ;;
	404)
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=bootstrap_key_absent socket_status=404"
		die 3 "$BOOTSTRAP_KEY is not set on this instance (HTTP 404): no nonce has been minted for it"
		;;
	403)
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=guest_api_forbidden socket_status=403"
		die 3 "guest API refused the key (HTTP 403): security.guestapi is false, or the key is outside user.*/cloud-init.*"
		;;
	401)
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=guest_api_unauthorized socket_status=401"
		die 3 "guest API refused the caller (HTTP 401): the bootstrap value is readable by guest root only"
		;;
	*)
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=guest_api_unexpected socket_status=$status"
		die 3 "unexpected guest API status $status"
		;;
	esac
}

# --- TLS pinning --------------------------------------------------------------

# pin_broker_certificate verifies the broker's leaf against the fingerprint
# carried in the bootstrap payload BEFORE anything is transmitted, then hands the
# SPKI hash of that same certificate to curl so the request must reach the
# certificate that was just verified. curl has no certificate-digest pin:
# --pinnedpubkey pins the SHA-256 of the SubjectPublicKeyInfo.
pin_broker_certificate() {
	local host="$1" port="$2" expected="$3"

	local sni="$host"
	[[ -n "$BROKER_TLS_HOSTNAME" ]] && sni="$BROKER_TLS_HOSTNAME"

	local -a s_client=(-connect "$host:$port")
	if ! is_ip_literal "$sni"; then
		s_client+=(-servername "$sni")
	fi

	PINNED_LEAF="$WORK_DIR/broker-leaf.pem"
	if ! "$OPENSSL_BIN" s_client "${s_client[@]}" </dev/null 2>"$WORK_DIR/s_client.err" |
		awk '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if (n==1) exit}' \
			>"$PINNED_LEAF"; then
		safe_print tls "$WORK_DIR/s_client.err" >&2 || true
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=tls_handshake_failed status=000 nonce_id=$NONCE_ID"
		die 15 "cannot fetch the broker certificate from $host:$port"
	fi

	[[ -s "$PINNED_LEAF" ]] || {
		safe_print tls "$WORK_DIR/s_client.err" >&2 || true
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=no_certificate status=000 nonce_id=$NONCE_ID"
		die 15 "the broker at $host:$port presented no certificate"
	}

	local observed want
	observed=$(normalize_fingerprint "$("$OPENSSL_BIN" x509 -in "$PINNED_LEAF" -noout -fingerprint -sha256 | cut -d= -f2)")
	want=$(normalize_fingerprint "$expected")
	log "tls: broker_fingerprint expected=$want observed=$observed"

	if [[ "$observed" != "$want" ]]; then
		log "RESULT phase=p9-bootstrap outcome=FAIL reason=fingerprint_mismatch status=000 nonce_id=$NONCE_ID"
		die 5 "broker certificate fingerprint does not match the pinned value in the bootstrap payload; the nonce was NOT sent"
	fi

	PINNED_SPKI=$("$OPENSSL_BIN" x509 -in "$PINNED_LEAF" -pubkey -noout |
		"$OPENSSL_BIN" pkey -pubin -outform der |
		"$OPENSSL_BIN" dgst -sha256 -binary |
		"$OPENSSL_BIN" enc -base64)
	log "tls: pinned SPKI sha256//$PINNED_SPKI"
}

# --- Redemption ---------------------------------------------------------------

diagnose_status() {
	case "$1" in
	401)
		log "verdict: REJECTED 401 unauthorized — an unknown nonce ID or a wrong secret. The broker"
		log "         answers one status for both so a caller cannot enumerate live nonce IDs."
		STATUS_EXIT=10
		;;
	409)
		log "verdict: REJECTED 409 conflict — the nonce exists and the secret matched, but the state"
		log "         forbids redemption: already consumed, expired, bound to another instance, or the"
		log "         generation moved. On a reboot this is the expected answer for a stale key: P9"
		log "         needs a FRESH nonce per bootstrap."
		STATUS_EXIT=11
		;;
	400)
		log "verdict: REJECTED 400 invalid request — the broker's decoder is strict and refused the"
		log "         body. Harness bug or an unaccepted field, not a lifecycle result."
		STATUS_EXIT=14
		;;
	500)
		log "verdict: ERROR 500 — broker internal failure. Not a security verdict: capture the broker"
		log "         log for this nonce ID before rerunning."
		STATUS_EXIT=12
		;;
	503)
		log "verdict: ERROR 503 — a broker dependency is unavailable: the nonce store, the Incus API,"
		log "         or the host agent's Broker API endpoint that mints the exchange SVID. Retryable."
		STATUS_EXIT=13
		;;
	*)
		log "verdict: UNEXPECTED $1 — not one of 200/401/409/500/503."
		STATUS_EXIT=14
		;;
	esac
}

# redeem posts the nonce and, on success, leaves the response body in a 0600 file
# inside the tmpfs. That body now contains a PRIVATE KEY, so it is never printed,
# never copied elsewhere, and never given to curl -v.
redeem() {
	local payload_file="$1" host="$2" port="$3" response="$4"

	local request_host="$host"
	local -a connect_to=()
	if [[ -n "$BROKER_TLS_HOSTNAME" && "$BROKER_TLS_HOSTNAME" != "$host" ]]; then
		request_host="$BROKER_TLS_HOSTNAME"
		connect_to=(--connect-to "$BROKER_TLS_HOSTNAME:$port:$host:$port")
	fi

	local url="https://$request_host:$port$REDEEM_PATH"
	log "redeem: POST $url nonce_id=$NONCE_ID"

	local -a tls=(--pinnedpubkey "sha256//$PINNED_SPKI")
	if [[ -n "$BROKER_CACERT" ]]; then
		[[ -r "$BROKER_CACERT" ]] || die 2 "BROKER_CACERT is not readable: $BROKER_CACERT"
		tls+=(--cacert "$BROKER_CACERT")
		log "redeem: chain validation against BROKER_CACERT=$BROKER_CACERT plus the SPKI pin"
	elif [[ "$ALLOW_INSECURE_TLS" == "1" ]]; then
		tls+=(--insecure)
		warn "ALLOW_INSECURE_TLS=1: curl chain and hostname validation are DISABLED for this request."
		warn "The broker is still pinned by certificate fingerprint and by SPKI hash, but record in the"
		warn "evidence that the run did not prove chain validation. Prefer BROKER_CACERT — this request"
		warn "carries a nonce out and brings a PRIVATE KEY back."
	else
		tls+=(--cacert "$PINNED_LEAF")
		log "redeem: using the pinned leaf as its own trust anchor (self-signed broker certificate)"
	fi

	local body status rc
	if ! body=$("$JQ_BIN" -c '{nonce_id: .nonce_id, nonce: .nonce}' <"$payload_file"); then
		die 4 "cannot build the redeem body from the bootstrap payload"
	fi

	set +e
	status=$(printf '%s' "$body" | "$CURL_BIN" --silent --show-error \
		--request POST \
		--header 'Content-Type: application/json' \
		--data-binary @- \
		--connect-timeout "$CONNECT_TIMEOUT" \
		--max-time "$MAX_TIME" \
		"${tls[@]}" "${connect_to[@]+"${connect_to[@]}"}" \
		--output "$response" \
		--write-out '%{http_code}' \
		"$url" 2>"$WORK_DIR/curl.err")
	rc=$?
	set -e
	body=""

	if ((rc != 0)) || [[ -z "$status" || "$status" == "000" ]]; then
		safe_print redeem "$WORK_DIR/curl.err" >&2 || true
		log "verdict: TRANSPORT FAILURE — no HTTP status. Supply the spike CA in BROKER_CACERT, set"
		log "         BROKER_TLS_HOSTNAME to the certificate's SAN, or set ALLOW_INSECURE_TLS=1"
		log "         deliberately."
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=transport_failure status=000 nonce_id=$NONCE_ID"
		exit 15
	fi

	log "redeem: HTTP $status"

	if body_leaks_secret "$response"; then
		warn "the broker response contained the nonce value. Body WITHHELD: Appendix D forbids a nonce"
		warn "value in any response body beyond the guest delivery, in a log, or in evidence."
		log "RESULT phase=p9-bootstrap outcome=FAIL reason=response_echoed_secret status=$status nonce_id=$NONCE_ID"
		exit 14
	fi

	case "$status" in
	200 | 201) return 0 ;;
	esac

	local reason
	reason=$(json_field "$response" error reason code message)
	diagnose_status "$status"
	log "RESULT phase=p9-bootstrap outcome=ERROR reason=redeem_rejected status=$status nonce_id=$NONCE_ID broker_reason=${reason:--}"
	exit "$STATUS_EXIT"
}

# --- Exchange material --------------------------------------------------------

# unpack_exchange_material splits the redeem response into the three files the
# x509pop agent plugin needs. Every one of them lands in the tmpfs at mode 0600.
# Nothing here is printed except metadata that Appendix D rule 3 permits:
# SPIFFE IDs, serials, validity windows and certificate counts.
unpack_exchange_material() {
	local response="$1"

	CERT_PATH="$EXCHANGE_DIR/svid.pem"
	KEY_PATH="$EXCHANGE_DIR/svid.key"
	BUNDLE_PATH="$EXCHANGE_DIR/bundle.pem"

	local missing=()
	extract_pem "$response" "$CERT_PATH" "$CHAIN_JQ" \
		svid_chain_pem certificate_chain_pem svid_pem certificate_pem chain_pem x509_svid_pem cert_chain_pem ||
		missing+=(certificate_chain)
	extract_pem "$response" "$KEY_PATH" "$KEY_JQ" \
		svid_key_pem private_key_pem key_pem x509_svid_key_pem svid_private_key_pem ||
		missing+=(private_key)
	extract_pem "$response" "$BUNDLE_PATH" "$BUNDLE_JQ" \
		trust_bundle_pem bundle_pem trust_bundle svid_bundle_pem x509_bundle_pem ||
		missing+=(trust_bundle)

	if ((${#missing[@]} > 0)); then
		# The body is never printed: it carries the key. Only the field names the
		# harness looked for and could not find.
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_material_missing missing=$(
			IFS=,
			printf '%s' "${missing[*]}"
		) nonce_id=$NONCE_ID"
		die 4 "the redeem response did not carry usable PEM material for: ${missing[*]} (body withheld: it may contain a private key). Override the lookup with CHAIN_JQ / KEY_JQ / BUNDLE_JQ."
	fi

	chmod 0600 -- "$CERT_PATH" "$KEY_PATH" "$BUNDLE_PATH"

	if ! "$OPENSSL_BIN" pkey -in "$KEY_PATH" -noout >/dev/null 2>&1; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_key_unparseable nonce_id=$NONCE_ID"
		die 4 "the delivered private key is not a parseable PEM key (value withheld)"
	fi

	# Proof of possession is the whole point of x509pop: the agent must sign the
	# server's challenge with this key. Checking the key against the certificate
	# here turns a silent attestation failure into a precise one, and prints only
	# yes/no.
	local cert_spki key_spki
	cert_spki=$("$OPENSSL_BIN" x509 -in "$CERT_PATH" -pubkey -noout 2>/dev/null | sha256_stdin)
	key_spki=$("$OPENSSL_BIN" pkey -in "$KEY_PATH" -pubout 2>/dev/null | sha256_stdin)
	if [[ -z "$cert_spki" || "$cert_spki" != "$key_spki" ]]; then
		log "RESULT phase=p9-bootstrap outcome=FAIL reason=key_certificate_mismatch nonce_id=$NONCE_ID"
		die 4 "the delivered private key does not match the delivered certificate; x509pop proof of possession would fail"
	fi
	log "exchange: private key parses and matches the certificate (public-key digests equal)"

	local chain_certs bundle_certs serial not_before
	chain_certs=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$CERT_PATH" || true)
	bundle_certs=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$BUNDLE_PATH" || true)
	serial=$("$OPENSSL_BIN" x509 -in "$CERT_PATH" -noout -serial 2>/dev/null | cut -d= -f2)
	not_before=$("$OPENSSL_BIN" x509 -in "$CERT_PATH" -noout -startdate 2>/dev/null | cut -d= -f2-)
	EXCHANGE_NOT_AFTER=$("$OPENSSL_BIN" x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2-)
	EXCHANGE_ID=$(spiffe_id_of_leaf "$CERT_PATH" || printf '')

	log "exchange: certificate_path=$CERT_PATH chain_certs=$chain_certs (leaf first; x509pop accepts leaf+intermediates in one file)"
	log "exchange: private_key_path=$KEY_PATH mode=0600 (memory-backed, never persisted)"
	log "exchange: trust_bundle_path=$BUNDLE_PATH bundle_certs=$bundle_certs"
	log "exchange: spiffe_id=${EXCHANGE_ID:-<absent>}"
	log "exchange: serial=${serial:--} not_before=${not_before:--} not_after=${EXCHANGE_NOT_AFTER:--}"

	if [[ -z "$EXCHANGE_ID" ]]; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_svid_has_no_uri_san nonce_id=$NONCE_ID"
		die 4 "the delivered certificate carries no spiffe:// URI SAN, so it is not an SVID"
	fi
}

# check_exchange_id compares the delivered SPIFFE ID with the form P9 fixed. A
# mismatch is a FAIL and the agent is NOT started: the server would derive a node
# path from this ID, so a wrong ID means a wrong node identity.
check_exchange_id() {
	local expected="spiffe://$TRUST_DOMAIN$EXCHANGE_ID_PREFIX/$INSTANCE_UUID"
	log "exchange: expected_spiffe_id=$expected"
	[[ "$EXCHANGE_ID" == "$expected" ]] && return 0

	if [[ "$ALLOW_UNEXPECTED_EXCHANGE_ID" == "1" ]]; then
		warn "the exchange SVID is $EXCHANGE_ID, not $expected. ALLOW_UNEXPECTED_EXCHANGE_ID=1, continuing;"
		warn "record the observed node path this produces."
		return 0
	fi
	log "RESULT phase=p9-bootstrap outcome=FAIL reason=unexpected_exchange_spiffe_id observed=$EXCHANGE_ID expected=$expected"
	die 23 "the broker delivered $EXCHANGE_ID; P9 expects $expected. Set ALLOW_UNEXPECTED_EXCHANGE_ID=1 to start the agent anyway."
}

# --- Agent configuration and start --------------------------------------------

# render_agent_conf substitutes the template's @@TOKEN@@ placeholders. The
# rendered file holds no secret — only paths — so it lives outside the tmpfs and
# survives the shred, which is what makes the failure mode after a restart
# legible: the config is there and the credential it names is not.
render_agent_conf() {
	local template="$1" out="$2" bundle_path="$3"

	[[ -r "$template" ]] || die 2 "agent.conf.template is not readable: $template (set AGENT_CONF_TEMPLATE)"

	local key_manager_data=""
	case "$AGENT_KEY_MANAGER" in
	memory) key_manager_data="" ;;
	disk) key_manager_data="directory = \"$AGENT_DATA_DIR\"" ;;
	*) die 2 "AGENT_KEY_MANAGER must be memory or disk, got: $AGENT_KEY_MANAGER" ;;
	esac

	local -a tokens=(
		"TRUST_DOMAIN=$TRUST_DOMAIN"
		"SERVER_ADDRESS=$SPIRE_SERVER_ADDRESS"
		"SERVER_PORT=$SPIRE_SERVER_PORT"
		"DATA_DIR=$AGENT_DATA_DIR"
		"SOCKET_PATH=$AGENT_SOCKET_PATH"
		"LOG_LEVEL=$AGENT_LOG_LEVEL"
		"TRUST_BUNDLE_PATH=$bundle_path"
		"EXCHANGE_CERT_PATH=$CERT_PATH"
		"EXCHANGE_KEY_PATH=$KEY_PATH"
		"KEY_MANAGER=$AGENT_KEY_MANAGER"
		"KEY_MANAGER_DATA=$key_manager_data"
		"HEALTH_BIND_ADDRESS=$AGENT_HEALTH_BIND_ADDRESS"
		"HEALTH_BIND_PORT=$AGENT_HEALTH_BIND_PORT"
	)

	local -a script=()
	local token name value
	for token in "${tokens[@]}"; do
		name="${token%%=*}"
		value="${token#*=}"
		# sed uses | as its delimiter, so a value containing one would corrupt the
		# rendering silently. Refuse instead.
		[[ "$value" == *"|"* ]] && die 2 "the value for @@$name@@ contains '|', which this renderer cannot substitute: $value"
		script+=(-e "s|@@$name@@|$value|g")
	done

	sed "${script[@]}" -- "$template" >"$out"
	chmod 0644 -- "$out"

	local unresolved
	unresolved=$(grep -o '@@[A-Z_]*@@' "$out" | sort -u | tr '\n' ' ' || true)
	if [[ -n "${unresolved// /}" ]]; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=unresolved_template_tokens tokens=${unresolved// /,}"
		die 2 "agent.conf still contains placeholders: $unresolved"
	fi

	log "agent: rendered $out from $template"
	log "agent: trust_domain=$TRUST_DOMAIN server=$SPIRE_SERVER_ADDRESS:$SPIRE_SERVER_PORT data_dir=$AGENT_DATA_DIR"
	log "agent: socket_path=$AGENT_SOCKET_PATH key_manager=$AGENT_KEY_MANAGER trust_bundle_path=$bundle_path"

	if "$SPIRE_AGENT_BIN" validate -config "$out" >"$WORK_DIR/validate.out" 2>&1; then
		log "agent: spire-agent validate -config accepted the rendered configuration"
	else
		safe_print agent_validate "$WORK_DIR/validate.out" >&2 || true
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=agent_config_invalid conf=$out"
		die 2 "spire-agent rejected the rendered configuration"
	fi
}

start_agent() {
	local conf="$1"

	mkdir -p -- "$AGENT_DATA_DIR"
	chmod 0700 -- "$AGENT_DATA_DIR"
	mkdir -p -- "$(dirname -- "$AGENT_SOCKET_PATH")"

	case "$AGENT_START_MODE" in
	background)
		require_tool setsid setsid PATH
		AGENT_LOG="$AGENT_RUN_DIR/spire-agent.log"
		: >"$AGENT_LOG"
		chmod 0600 -- "$AGENT_LOG"
		# setsid detaches the agent from this session so it survives `incus exec`
		# returning, which sends SIGHUP to the process group. setsid --fork means
		# $! would be setsid's short-lived pid, not the agent's, so the agent
		# records its own pid and then execs: the pidfile holds the real pid.
		local pidfile="$AGENT_RUN_DIR/agent.pid"
		rm -f -- "$pidfile"
		setsid --fork bash -c 'printf "%s\n" "$$" >"$1"; shift; exec "$@"' \
			spike-agent-launcher "$pidfile" \
			"$SPIRE_AGENT_BIN" run -config "$conf" >>"$AGENT_LOG" 2>&1
		local waited=0
		while ((waited < 10)) && [[ ! -s "$pidfile" ]]; do
			sleep 1
			waited=$((waited + 1))
		done
		AGENT_PID=$(cat -- "$pidfile" 2>/dev/null || printf '')
		[[ -n "$AGENT_PID" ]] || die 20 "the agent process did not start (see $AGENT_LOG)"
		log "agent: started $SPIRE_AGENT_BIN run -config $conf pid=$AGENT_PID log=$AGENT_LOG"
		;;
	systemd)
		require_tool systemd-run systemd-run PATH
		require_tool journalctl journalctl PATH
		require_tool systemctl systemctl PATH
		systemd-run --unit="$AGENT_UNIT" --collect --property=Restart=no \
			-- "$SPIRE_AGENT_BIN" run -config "$conf" >/dev/null
		log "agent: started transient unit $AGENT_UNIT (systemd-run --collect, no unit file left behind)"
		;;
	none)
		log "agent: AGENT_START_MODE=none — configuration rendered and exchange material delivered, nothing started"
		;;
	*)
		die 2 "AGENT_START_MODE must be background, systemd or none, got: $AGENT_START_MODE"
		;;
	esac
}

agent_log_tail() {
	case "$AGENT_START_MODE" in
	background) [[ -n "$AGENT_LOG" && -r "$AGENT_LOG" ]] && cat -- "$AGENT_LOG" ;;
	systemd) journalctl -u "$AGENT_UNIT" --no-pager -n 400 2>/dev/null ;;
	esac
	return 0
}

# node_id_from_data_dir reads the node SPIFFE ID out of the agent's own cache.
# SPIRE 1.15.2 stores it in $data_dir/agent-data.json as base64-wrapped PEM under
# .svid — certificates only, no key material, mode 0600. This is the
# authoritative in-guest answer to "what identity did the agent get".
node_id_from_data_dir() {
	local data="$AGENT_DATA_DIR/agent-data.json"
	[[ -s "$data" ]] || return 1
	local pem="$WORK_DIR/agent-svid.pem"
	"$JQ_BIN" -r '.svid[0] // ""' <"$data" 2>/dev/null | base64 -d >"$pem" 2>/dev/null || return 1
	[[ -s "$pem" ]] || return 1
	spiffe_id_of_leaf "$pem"
}

# node_id_from_log is the fallback: SPIRE 1.15.2 logs "Node attestation was
# successful" (and "SVID loaded" when it recovered one) with a spiffe_id field.
node_id_from_log() {
	local found
	found=$(agent_log_tail |
		grep -E 'Node attestation was successful|SVID loaded' |
		grep -o 'spiffe://[^" ]*' | tail -n 1) || return 1
	[[ -n "$found" ]] || return 1
	printf '%s' "$found"
}

agent_alive() {
	case "$AGENT_START_MODE" in
	background) [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null ;;
	systemd) systemctl is-active --quiet "$AGENT_UNIT" ;;
	*) return 0 ;;
	esac
}

# wait_for_attestation polls the two independent signals P9 needs: the node SVID
# the agent obtained, and a ready Workload API. Both must appear, because the
# phase's acceptance is an in-guest app fetching an SVID from a standard local
# Workload API — an attested agent with a dead socket proves half of it.
wait_for_attestation() {
	local deadline=$(($(date +%s) + AGENT_READY_TIMEOUT))
	local ready=0 found=""

	while (($(date +%s) < deadline)); do
		if [[ -z "$found" ]]; then
			found=$(node_id_from_data_dir 2>/dev/null || printf '')
			[[ -z "$found" ]] && found=$(node_id_from_log 2>/dev/null || printf '')
			if [[ -n "$found" ]]; then
				NODE_ID="$found"
				log "agent: node attestation succeeded, node_spiffe_id=$NODE_ID"
			fi
		fi

		if [[ -n "$found" ]] && ((ready == 0)); then
			if "$SPIRE_AGENT_BIN" healthcheck -socketPath "$AGENT_SOCKET_PATH" >/dev/null 2>&1; then
				ready=1
				log "agent: healthcheck ready on $AGENT_SOCKET_PATH (standard Workload API is serving)"
				break
			fi
		fi

		if ! agent_alive; then
			log "agent: the process is gone"
			break
		fi
		sleep 2
	done

	if [[ -z "$NODE_ID" || "$NODE_ID" == "-" ]]; then
		agent_log_tail | safe_stream agent_log | tail -n 40 >&2 || true
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=agent_not_attested timeout_seconds=$AGENT_READY_TIMEOUT exchange_spiffe_id=$EXCHANGE_ID"
		die 20 "the guest agent did not attest within ${AGENT_READY_TIMEOUT}s (see the log above; x509pop needs the server to have mode=\"spiffe\" and a registration entry for $EXCHANGE_ID)"
	fi

	if ((ready == 0)); then
		agent_log_tail | safe_stream agent_log | tail -n 40 >&2 || true
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=workload_api_not_ready node_spiffe_id=$NODE_ID timeout_seconds=$AGENT_READY_TIMEOUT"
		die 20 "the agent attested as $NODE_ID but its Workload API never became ready at $AGENT_SOCKET_PATH"
	fi
}

check_node_id() {
	local expected="spiffe://$TRUST_DOMAIN$NODE_ID_PREFIX/$INSTANCE_UUID"
	log "agent: expected_node_spiffe_id=$expected"
	[[ "$NODE_ID" == "$expected" ]] && return 0
	log "RESULT phase=p9-bootstrap outcome=FAIL reason=unexpected_node_spiffe_id observed=$NODE_ID expected=$expected exchange_spiffe_id=$EXCHANGE_ID"
	die 21 "the agent attested as $NODE_ID; P9 expects $expected (server x509pop svid_prefix/agent_path_template mismatch is configuration, not architecture)"
}

# --- Main ---------------------------------------------------------------------

usage() {
	cat <<'EOF'
usage: guest-agent-bootstrap.sh

Runs as root inside a spike guest. Every knob is an environment variable.

Required:
  SPIRE_SERVER_ADDRESS      SPIRE server address the guest agent dials

Frequently set:
  SPIRE_SERVER_PORT         default 8081
  TRUST_DOMAIN              default spike.incus.internal
  BROKER_CACERT             spike CA for chain validation (recommended)
  AGENT_CONF_TEMPLATE       default agent.conf.template beside this script
  SPIRE_AGENT_BIN           default spire-agent
  AGENT_START_MODE          background (default) | systemd | none
  AGENT_KEY_MANAGER         memory (default) | disk
  AGENT_DATA_DIR            default /var/lib/spire-agent
  AGENT_SOCKET_PATH         default /tmp/spire-agent/public/api.sock
  AGENT_READY_TIMEOUT       default 90 seconds
  EXCHANGE_DIR              default /run/spike-exchange (mounted tmpfs)
  PERSIST_TRUST_BUNDLE      default 1; public material only, never the key
  PAYLOAD_FILE              read the bootstrap payload from a file, not the socket
  KEEP_EXCHANGE_MATERIAL    1 keeps the tmpfs on a FAILED run, for debugging
  CHAIN_JQ KEY_JQ BUNDLE_JQ explicit jq filters for the PEM fields
  CURL_BIN JQ_BIN OPENSSL_BIN CONNECT_TIMEOUT MAX_TIME

No path prints the nonce, the exchange private key, or a response body; see the
secret-handling and exchange-key notes at the top of this file.
EOF
}

main() {
	if (($# > 0)); then
		case "$1" in
		-h | --help)
			usage
			exit 0
			;;
		*) die 2 "unexpected argument: $1 (this script is configured by environment variables; try --help)" ;;
		esac
	fi

	case "$AGENT_START_MODE" in
	background | systemd | none) ;;
	*) die 2 "AGENT_START_MODE must be background, systemd or none, got: $AGENT_START_MODE" ;;
	esac
	case "$AGENT_KEY_MANAGER" in
	memory | disk) ;;
	*) die 2 "AGENT_KEY_MANAGER must be memory or disk, got: $AGENT_KEY_MANAGER" ;;
	esac
	[[ -n "$SPIRE_SERVER_ADDRESS" ]] ||
		die 2 "SPIRE_SERVER_ADDRESS is required: a wrong default would surface as an attestation timeout instead of a configuration error"

	if [[ -z "$AGENT_CONF_TEMPLATE" ]]; then
		AGENT_CONF_TEMPLATE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/agent.conf.template"
	fi

	require_tool "$CURL_BIN" curl CURL_BIN
	require_tool "$JQ_BIN" jq JQ_BIN
	require_tool "$OPENSSL_BIN" openssl OPENSSL_BIN
	require_tool "$SPIRE_AGENT_BIN" "the guest SPIRE agent" SPIRE_AGENT_BIN
	require_tool mount mount PATH
	require_tool umount umount PATH
	require_tool shred shred PATH
	require_tool base64 base64 PATH
	require_tool find find PATH

	[[ $(id -u) == 0 ]] || die 2 "this script must run as guest root: it mounts a tmpfs and reads $GUEST_SOCKET"

	# The tmpfs comes first, before the nonce is read and before anything is
	# requested. Everything secret-bearing in this run — the bootstrap payload,
	# the redeem response body, the exchange key — lives only here.
	trap on_exit EXIT
	mount_exchange_tmpfs

	mkdir -p -- "$AGENT_RUN_DIR"
	chmod 0700 -- "$AGENT_RUN_DIR"

	local staged="$WORK_DIR/bootstrap.json"
	if [[ -n "$PAYLOAD_FILE" ]]; then
		[[ -r "$PAYLOAD_FILE" ]] || die 3 "PAYLOAD_FILE is not readable: $PAYLOAD_FILE"
		log "source: staged payload $PAYLOAD_FILE (the guest socket was not read)"
		cat -- "$PAYLOAD_FILE" >"$staged"
	else
		read_payload_to_file "$staged"
	fi
	[[ -s "$staged" ]] || die 4 "the bootstrap value is empty"

	local digest
	digest=$(sha256_stdin <"$staged")

	if ! "$JQ_BIN" -e 'type == "object"' >/dev/null 2>&1 <"$staged"; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=payload_not_json payload_sha256=$digest"
		die 4 "the bootstrap value is not a JSON object (payload withheld; sha256=$digest)"
	fi

	NONCE_ID=$(json_field "$staged" nonce_id)
	local broker_url fingerprint secret_present=0
	broker_url=$(json_field "$staged" broker_url)
	fingerprint=$(json_field "$staged" broker_fingerprint)

	if "$JQ_BIN" -e '(.nonce? // "") != ""' >/dev/null 2>&1 <"$staged"; then
		secret_present=1
		SECRET_FILE="$WORK_DIR/nonce"
		"$JQ_BIN" -r '.nonce' <"$staged" >"$SECRET_FILE"
	fi

	log "payload: nonce_id=${NONCE_ID:-<absent>}"
	log "payload: sha256=$digest"
	log "payload: broker_url=${broker_url:-<absent>}"
	log "payload: broker_fingerprint=${fingerprint:-<absent>}"
	log "payload: nonce=<redacted$( ((secret_present)) && printf ', present' || printf ', ABSENT')>"

	local missing=()
	[[ -n "$NONCE_ID" ]] || missing+=(nonce_id)
	((secret_present)) || missing+=(nonce)
	[[ -n "$broker_url" ]] || missing+=(broker_url)
	[[ -n "$fingerprint" ]] || missing+=(broker_fingerprint)
	if ((${#missing[@]} > 0)); then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=missing_payload_fields nonce_id=${NONCE_ID:--} payload_sha256=$digest missing=${missing[*]}"
		die 4 "the bootstrap payload is missing: ${missing[*]}"
	fi

	local url="${BROKER_URL_OVERRIDE:-$broker_url}"
	[[ "$url" == https://* ]] || die 4 "broker URL is not https: $url"
	local host_port="${url#https://}"
	host_port="${host_port%%/*}"
	local host="${host_port%%:*}"
	local port="${host_port##*:}"
	[[ "$port" != "$host_port" ]] || port=443
	log "broker: host=$host port=$port"

	pin_broker_certificate "$host" "$port" "$fingerprint"

	local response="$WORK_DIR/redeem.json"
	redeem "$staged" "$host" "$port" "$response"

	# Binding metadata and selectors are permitted evidence (Appendix D rule 3).
	local resolved_name resolved_generation resolved_project selectors
	INSTANCE_UUID=$(json_field "$response" instance_uuid uuid)
	resolved_name=$(json_field "$response" instance_name name)
	resolved_generation=$(json_field "$response" generation generation_uuid)
	resolved_project=$(json_field "$response" project)
	selectors=$("$JQ_BIN" -r '[(.selectors? // [])[] | tostring] | join(",")' <"$response" 2>/dev/null || printf '')
	log "verdict: GRANTED"
	log "  resolved_instance_uuid=${INSTANCE_UUID:-<absent>}"
	log "  resolved_instance_name=${resolved_name:-<absent>}"
	log "  resolved_generation=${resolved_generation:-<absent>}"
	log "  project=${resolved_project:-<absent>}"
	log "  selectors=${selectors:-<absent>}"

	unpack_exchange_material "$response"

	# The response file has served its purpose and still contains the key. It goes
	# now rather than at the end of the run.
	shred -u -z -n 1 -- "$response" 2>/dev/null || rm -f -- "$response"

	if [[ -z "$INSTANCE_UUID" ]]; then
		# Fall back to the UUID the exchange SVID itself carries, so the expected
		# node path can still be computed and checked.
		INSTANCE_UUID="${EXCHANGE_ID##*/}"
		warn "the redeem response carried no instance_uuid; taking $INSTANCE_UUID from the exchange SVID path"
	fi
	check_exchange_id

	local bundle_path="$BUNDLE_PATH"
	if [[ "$PERSIST_TRUST_BUNDLE" == "1" ]]; then
		mkdir -p -- "$AGENT_DATA_DIR"
		chmod 0700 -- "$AGENT_DATA_DIR"
		bundle_path="$AGENT_DATA_DIR/bundle.pem"
		cat -- "$BUNDLE_PATH" >"$bundle_path"
		chmod 0644 -- "$bundle_path"
		log "agent: trust bundle persisted to $bundle_path (public material, Appendix D rule 3) so the agent can be restarted"
	else
		log "agent: PERSIST_TRUST_BUNDLE=0 — the bundle stays in the tmpfs, so after the shred the agent cannot even start again"
	fi

	local conf="$AGENT_RUN_DIR/agent.conf"
	render_agent_conf "$AGENT_CONF_TEMPLATE" "$conf" "$bundle_path"
	start_agent "$conf"

	if [[ "$AGENT_START_MODE" == "none" ]]; then
		warn "the exchange key is LIVE in $EXCHANGE_DIR because nothing was started. It is memory-backed"
		warn "and dies with the guest; destroy it as soon as you are done:"
		warn "  find $EXCHANGE_DIR -type f -exec shred -u -z -n 1 {} + && umount $EXCHANGE_DIR"
		log "RESULT phase=p9-bootstrap outcome=STAGED nonce_id=$NONCE_ID instance_uuid=$INSTANCE_UUID exchange_spiffe_id=$EXCHANGE_ID exchange_not_after=$EXCHANGE_NOT_AFTER conf=$conf exchange_material=live_in_tmpfs"
		return 0
	fi

	wait_for_attestation
	check_node_id

	# Attestation is done, so the credential has served its single use. Reclaim it
	# here rather than leaving it to the exit trap, so the RESULT line can state
	# the observed outcome instead of an intention.
	if ! reclaim_exchange_material; then
		log "RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_material_not_reclaimed node_spiffe_id=$NODE_ID exchange_material=live"
		exit 8
	fi

	log "note: the exchange credential is gone and the agent keeps running on the node SVID it obtained."
	log "note: a restart or reboot therefore needs a FRESH nonce and a new exchange SVID — that is the"
	log "      P9 step-4 re-attestation story, chosen rather than discovered. AGENT_KEY_MANAGER=$AGENT_KEY_MANAGER."

	log "RESULT phase=p9-bootstrap outcome=PASS nonce_id=$NONCE_ID instance_uuid=$INSTANCE_UUID exchange_spiffe_id=$EXCHANGE_ID exchange_not_after=$EXCHANGE_NOT_AFTER node_spiffe_id=$NODE_ID key_manager=$AGENT_KEY_MANAGER workload_api=$AGENT_SOCKET_PATH exchange_material=$RECLAIMED"
}

CERT_PATH=""
KEY_PATH=""
BUNDLE_PATH=""

main "$@"

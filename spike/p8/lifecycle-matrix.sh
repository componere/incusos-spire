#!/usr/bin/env bash
#
# lifecycle-matrix.sh — P8 lifecycle harness. Drives the nonce lifecycle cases of
# SPIKE_PLAN.md P8 steps 4 and 5 end to end against a live Incus host and a live
# incus-spiffe-broker, printing exactly one outcome per case.
#
# THROWAWAY spike tooling. Appendix C of SPIKE_PLAN.md classifies everything
# under spike/ as never merged as product code: it is deletable without loss,
# because the evidence it produces lives in the journal. Do not import, wrap, or
# promote any of this.
#
# ---------------------------------------------------------------------------
# SECRET HANDLING — Appendix D rules 1 and 5
# ---------------------------------------------------------------------------
# This script never sees a nonce value, and that is by construction, not by
# accident:
#
#   * Payloads are read only inside a guest, by guest-bootstrap.sh, which prints
#     nonce IDs and digests and never the value.
#   * When a case needs a payload somewhere else (a leaked token, a nonce whose
#     instance was deleted, a payload that must survive a snapshot restore), the
#     bytes move guest-to-guest through a pipe: `incus file pull ... -` straight
#     into `incus file push - ...`. They never land on the operator's disk and
#     never pass through a printed variable.
#   * Cleanup proves the bootstrap key is gone by piping `incus config get`
#     straight into `grep -q`, so even the verification never captures or prints
#     the value it is checking for.
#   * Everything this script echoes from a guest is guest-bootstrap.sh output,
#     which is transcript-safe.
#   * The cleanup trap removes the guest staging directories that hold those
#     payload files, and clears user.spiffe-bootstrap on every instance it
#     touched, even when a case aborts (P8 rollback requirement).
#
# ---------------------------------------------------------------------------
# THREE OUTCOMES, NEVER TWO
# ---------------------------------------------------------------------------
# A verdict is only evidence if it distinguishes "the control decided correctly"
# from "the control never got to decide". Every case therefore ends in exactly
# one of:
#
#   PASS      the security decision under test was observed and was correct.
#   FAIL      the security decision was observed and was WRONG: a rejection that
#             was granted, a grant with the wrong identity, or a concurrency
#             result other than exactly one success.
#   ERROR     no security decision was observed. A precondition, a dependency or
#             the broker itself failed: a missing guest binary, an unreachable
#             socket, a mint that never happened, HTTP 000/400/5xx where a
#             401/409 rejection was the only meaningful answer.
#   MEASURED  case i only: a recorded observation of a known limitation, never a
#             pass and never a failure (see case_i).
#
# An ERROR is NEVER reported as a PASS and always makes the run exit non-zero,
# unless the operator explicitly sets ALLOW_CASE_ERRORS=1 — which is recorded in
# the summary as "this run is not complete evidence".
#
# A rejection carrying an unexpected but still meaningful status (401 where 409
# was documented) is a NOTE, because reject-versus-grant is the security property
# and the exact code is a contract detail; STRICT_STATUS=1 promotes those notes
# to failures. A status that is not a decision at all (000, 400, 500, 503) is an
# ERROR regardless of STRICT_STATUS.
#
# ---------------------------------------------------------------------------
# GUEST DEPENDENCY PREFLIGHT
# ---------------------------------------------------------------------------
# guest-bootstrap.sh needs curl, jq and openssl inside the guest. The P8 live run
# lost case e to exactly this: stock images:debian/13 has no jq. Every guest this
# harness touches is therefore assessed once — instance present, /dev/incus/sock
# up, GUEST_DEPS present, harness stageable — and a case that needs an unusable
# guest is recorded as ERROR naming the exact missing dependency. Set
# GUEST_INSTALL_DEPS=1 to let the harness install the missing ones with
# GUEST_INSTALL_CMD (apt-get, so Debian and Ubuntu guests) before giving up.
# Installing mutates the guest and is never implicit.
#
# ---------------------------------------------------------------------------
# OPERATOR CREDENTIAL
# ---------------------------------------------------------------------------
# The mint endpoint is authenticated. Preflight requires MINT_AUTH_TOKEN_FILE
# (preferred) or MINT_AUTH_TOKEN and fails the run without one, because an
# unauthenticated mint answers 401 and every case would then ERROR for the same
# uninformative reason. The value is passed to operator-mint.sh, which sends it
# through a curl --config file so it never reaches argv, and it is never printed.
#
# ---------------------------------------------------------------------------
# CASES (SPIKE_PLAN.md P8 step 4 and step 5)
# ---------------------------------------------------------------------------
#   a  positive: mint for guest A, then A redeems through its own /dev/incus/sock
#   b  second redemption of the same nonce is rejected
#   c  expired nonce is rejected
#   d  two CONCURRENT redemptions of one nonce yield exactly one success
#   e  nonce for a DELETED instance is rejected
#   f  nonce invalidated when volatile.uuid.generation changes (snapshot restore,
#      which P6 proved always installs a fresh generation)
#   g  guest B cannot read A's nonce through its own /dev/incus/sock
#   h  guest B supplies its OWN nonce while claiming A's UUID: the broker must
#      resolve only B
#   i  MEASUREMENT, NOT A PASS/FAIL CASE: a deliberately leaked, unused A nonce
#      redeemed from B. SPIKE_PLAN.md P8 step 5 says an unused leaked nonce is a
#      bearer credential and EXPECTS it to succeed. This script records the
#      outcome honestly as a go/no-go input; only a failure to measure it at all
#      is an ERROR.
#
# Exit status: 0 every selected case passed (or was measured), 1 any case FAILed
# or ERRORed, 2 preflight or usage failure, 3 cleanup was incomplete — a nonce
# secret or a payload file may still be live somewhere.

set -euo pipefail
umask 077

# --- Parameters ---------------------------------------------------------------

INCUS_BIN="${INCUS_BIN:-incus}"
# Remote name of the spike host. Set to the empty string to drive the local
# daemon. A trailing colon is added automatically.
INCUS_REMOTE="${INCUS_REMOTE:-ovh-incusos}"
PROJECT="${PROJECT:-spike-spiffe}"

GUEST_A="${GUEST_A:-spike-guest-a}"
GUEST_B="${GUEST_B:-spike-guest-b}"
# Resolved from volatile.uuid when left empty.
GUEST_A_UUID="${GUEST_A_UUID:-}"
GUEST_B_UUID="${GUEST_B_UUID:-}"

# Disposable instance for the deleted-instance case. It is created and destroyed
# by this script; never point this at a guest you want to keep.
TMP_INSTANCE="${TMP_INSTANCE:-spike-guest-tmp}"
TMP_IMAGE="${TMP_IMAGE:-images:debian/13}"
TMP_TYPE="${TMP_TYPE:-container}"

# Broker. These are exported for operator-mint.sh; the guest reads broker_url and
# broker_fingerprint out of its own payload, so GUEST_BROKER_URL is only for a
# split-horizon spike bridge where the payload URL is unreachable from a guest.
export BROKER_URL="${BROKER_URL:-https://spike-broker:8443}"
export NONCE_PATH="${NONCE_PATH:-/v1alpha1/nonce}"
export BROKER_CACERT="${BROKER_CACERT:-}"
export BROKER_FINGERPRINT="${BROKER_FINGERPRINT:-}"
export BROKER_TLS_HOSTNAME="${BROKER_TLS_HOSTNAME:-}"
export ALLOW_INSECURE_TLS="${ALLOW_INSECURE_TLS:-0}"
export MINT_AUTH_TOKEN_FILE="${MINT_AUTH_TOKEN_FILE:-}"
export MINT_AUTH_TOKEN="${MINT_AUTH_TOKEN:-}"
export CURL_BIN="${CURL_BIN:-curl}"
export JQ_BIN="${JQ_BIN:-jq}"
export OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
REDEEM_PATH="${REDEEM_PATH:-/v1alpha1/redeem}"
GUEST_BROKER_URL="${GUEST_BROKER_URL:-}"

# TTLs. MINT_TTL_SECONDS is sent with every mint except case c, which asks for
# SHORT_TTL_SECONDS. ttl_seconds is a real, bounded mint field: the broker
# clamps it to its configured maximum, so case c derives its wait from the
# expires_at the broker actually returned rather than from what it asked for.
# EXPIRY_WAIT_SECONDS overrides that derivation; MAX_EXPIRY_WAIT_SECONDS stops
# the case hanging for a ten-minute default TTL and turns it into an ERROR.
MINT_TTL_SECONDS="${MINT_TTL_SECONDS:-}"
SHORT_TTL_SECONDS="${SHORT_TTL_SECONDS:-5}"
EXPIRY_WAIT_SECONDS="${EXPIRY_WAIT_SECONDS:-}"
MAX_EXPIRY_WAIT_SECONDS="${MAX_EXPIRY_WAIT_SECONDS:-120}"

BOOTSTRAP_KEY="${BOOTSTRAP_KEY:-user.spiffe-bootstrap}"
GUEST_STAGE_DIR="${GUEST_STAGE_DIR:-/root/p8}"
GUEST_READY_TIMEOUT="${GUEST_READY_TIMEOUT:-180}"

# Binaries guest-bootstrap.sh needs inside each guest, and the explicit opt-in
# that installs the missing ones. GUEST_INSTALL_CMD is an apt-get line because
# the spike guests are Debian; the missing binary names are appended to it.
GUEST_DEPS="${GUEST_DEPS:-curl jq openssl}"
GUEST_INSTALL_DEPS="${GUEST_INSTALL_DEPS:-0}"
GUEST_INSTALL_CMD="${GUEST_INSTALL_CMD:-apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends}"

CASES="${CASES:-a b c d e f g h i}"
STRICT_STATUS="${STRICT_STATUS:-0}"
# Explicit opt-out: report ERROR cases but do not let them change the exit
# status. Use it only when a partial matrix is deliberate; the summary says the
# run is not complete evidence.
ALLOW_CASE_ERRORS="${ALLOW_CASE_ERRORS:-0}"
# Leave the staging directories, the disposable instance and the snapshot in
# place for debugging. Those staging directories contain nonce payloads, so this
# is a deliberate, temporary choice. It never suppresses the verified clearing of
# the bootstrap key.
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"

HARNESS_DIR="${HARNESS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
GUEST_SCRIPT="$HARNESS_DIR/guest-bootstrap.sh"
MINT_SCRIPT="$HARNESS_DIR/operator-mint.sh"

REMOTE_PREFIX=""
[[ -n "$INCUS_REMOTE" ]] && REMOTE_PREFIX="${INCUS_REMOTE%:}:"

GUEST_SCRIPT_IN_GUEST="$GUEST_STAGE_DIR/guest-bootstrap.sh"
GUEST_CACERT_IN_GUEST="$GUEST_STAGE_DIR/broker-ca.pem"

# One row per case, in run order. CASE_OUTCOME holds PENDING until the case
# records something, so a case that silently returns is still visible.
declare -a CASE_ORDER=()
declare -a CASE_OUTCOME=()
declare -a CASE_DETAIL=()

declare -a NOTES=()
declare -a GUEST_ENV=()
declare -a PREPARED_GUESTS=()
# Every instance whose bootstrap key this run may have set. Cleanup clears and
# verifies each one.
declare -a TOUCHED_INSTANCES=()
# "<instance> <snapshot>" pairs created by this run.
declare -a SNAPSHOTS_CREATED=()
declare -a CLEANUP_FAILURES=()
# Per-guest usability cache; DEP_STATE is empty for a usable guest.
declare -a DEP_GUEST=()
declare -a DEP_STATE=()

GUEST_PROBLEM=""
TMP_CREATED=0
GUEST_OUT=""
GUEST_RC=0
MINT_OUT=""
MINT_RC=0
MINT_NONCE_ID=""
MINT_EXPIRES_AT=""
MINT_INSTANCE_NAME=""
MINT_GENERATION=""

# --- Output -------------------------------------------------------------------

log() {
	printf '%s\n' "$*"
}

section() {
	printf '\n=== %s\n' "$*"
}

step() {
	printf -- '--- %s\n' "$*"
}

# outcome_rank orders the outcomes so that a case keeps its worst one: a PASS
# printed before a strict-status failure, or before a late setup error, cannot
# hide it. PENDING loses to everything.
outcome_rank() {
	case "$1" in
	PENDING) printf '0' ;;
	MEASURED) printf '1' ;;
	PASS) printf '2' ;;
	FAIL) printf '3' ;;
	ERROR) printf '4' ;;
	*) printf '0' ;;
	esac
}

# record stores one outcome for a case, keeping the worst seen.
record() {
	local name="$1" outcome="$2" detail="$3"
	local i n=${#CASE_ORDER[@]}
	for ((i = 0; i < n; i++)); do
		if [[ "${CASE_ORDER[i]}" == "$name" ]]; then
			if (($(outcome_rank "$outcome") > $(outcome_rank "${CASE_OUTCOME[i]}"))); then
				CASE_OUTCOME[i]="$outcome"
				CASE_DETAIL[i]="$detail"
			fi
			return 0
		fi
	done
	CASE_ORDER+=("$name")
	CASE_OUTCOME+=("$outcome")
	CASE_DETAIL+=("$detail")
}

pass() {
	printf 'PASS  case %s: %s\n' "$1" "$2"
	record "$1" PASS "$2"
}

fail() {
	printf 'FAIL  case %s: %s\n' "$1" "$2"
	record "$1" FAIL "$2"
}

# case_error marks a case as unmeasured. It is the outcome for every dependency,
# precondition or backend failure: those are not security verdicts and must never
# be printed as a PASS.
case_error() {
	printf 'ERROR case %s: %s\n' "$1" "$2"
	record "$1" ERROR "$2"
}

measured() {
	printf 'MEASURED  case %s: %s\n' "$1" "$2"
	record "$1" MEASURED "$2"
}

note() {
	printf 'NOTE  case %s: %s\n' "$1" "$2"
	NOTES+=("case $1: $2")
}

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 2
}

# expect_status compares an observed rejection status with the documented one.
# It is only ever called for a status that already qualifies as a decision, so a
# mismatch is a contract detail: a note by default, a failure under
# STRICT_STATUS=1.
expect_status() {
	local name="$1" want="$2" got="$3"
	[[ "$want" == "$got" ]] && return 0
	if [[ "$STRICT_STATUS" == "1" ]]; then
		fail "$name" "expected HTTP $want, observed HTTP $got (STRICT_STATUS=1)"
	else
		note "$name" "expected HTTP $want, observed HTTP $got — rejection stands, contract detail differs"
	fi
}

# rejection_kind classifies a redemption that did not grant. It prints "decision"
# when the broker actually judged the nonce (401 or 409) and "error" for anything
# else: a harness or dependency failure inside the guest, no HTTP status at all,
# a 400 the broker could not parse, or a 5xx backend fault. Only "decision" may
# become a PASS.
rejection_kind() {
	local status="$1" reason="${2:-}"
	case "$reason" in
	missing_dependency | transport_failure | tls_handshake_failed | no_certificate | fingerprint_mismatch | payload_not_json | missing_fields | response_echoed_secret)
		printf 'error'
		return 0
		;;
	esac
	case "$status" in
	401 | 409) printf 'decision' ;;
	*) printf 'error' ;;
	esac
}

# reject_detail renders the guest's non-grant for a message.
reject_detail() {
	local rc="$1" status="$2" reason="$3"
	printf 'guest exit %s, HTTP %s, reason=%s' "$rc" "${status:-none}" "${reason:--}"
}

# --- Incus plumbing -----------------------------------------------------------

target() {
	printf '%s%s' "$REMOTE_PREFIX" "$1"
}

# config_get captures a config value into a variable, so it is for NON-SECRET
# keys only: volatile.uuid and volatile.uuid.generation, both permitted evidence
# under Appendix D rule 3. The bootstrap key is never read this way — see
# clear_key_verified, which checks its absence without capturing it.
config_get() {
	"$INCUS_BIN" config get "$(target "$1")" "$2" --project "$PROJECT" 2>/dev/null | tr -d '\r\n'
}

# clear_key clears the bootstrap key before a case mints over it. It reports a
# failure rather than hiding it; cleanup does the verified clear that the P8
# rollback requirement actually depends on.
clear_key() {
	local guest="$1"
	if "$INCUS_BIN" config unset "$(target "$guest")" "$BOOTSTRAP_KEY" --project "$PROJECT" >/dev/null 2>&1; then
		return 0
	fi
	log "    WARNING: could not clear $BOOTSTRAP_KEY on $guest; cleanup will verify it at the end"
	return 1
}

instance_exists() {
	"$INCUS_BIN" info "$(target "$1")" --project "$PROJECT" >/dev/null 2>&1
}

# register_touched records an instance whose bootstrap key cleanup must clear and
# verify, whatever else happens to the run.
register_touched() {
	local inst="$1" i n=${#TOUCHED_INSTANCES[@]}
	for ((i = 0; i < n; i++)); do
		[[ "${TOUCHED_INSTANCES[i]}" == "$inst" ]] && return 0
	done
	TOUCHED_INSTANCES+=("$inst")
}

# wait_for_guest waits until the guest API socket exists inside the instance. For
# a VM that also proves incus-agent came up, which GUEST_SOCK_BRIEF.md makes a
# prerequisite for any guest read.
wait_for_guest() {
	local guest="$1" deadline=$((SECONDS + GUEST_READY_TIMEOUT))
	while ! "$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- test -S /dev/incus/sock >/dev/null 2>&1; do
		((SECONDS < deadline)) || return 1
		sleep 3
	done
	return 0
}

# prepare_guest installs the guest harness and, when supplied, the broker CA into
# a 0700 staging directory inside the instance. It returns non-zero instead of
# aborting the run: a guest that cannot be staged is a case ERROR, not a crash.
prepare_guest() {
	local guest="$1"
	"$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
		install -d -m 0700 "$GUEST_STAGE_DIR" >/dev/null 2>&1 || return 1
	"$INCUS_BIN" file push "$GUEST_SCRIPT" "$(target "$guest")$GUEST_SCRIPT_IN_GUEST" \
		--project "$PROJECT" --mode 0700 >/dev/null 2>&1 || return 1
	if [[ -n "$BROKER_CACERT" ]]; then
		"$INCUS_BIN" file push "$BROKER_CACERT" "$(target "$guest")$GUEST_CACERT_IN_GUEST" \
			--project "$PROJECT" --mode 0600 >/dev/null 2>&1 || return 1
	fi
	local seen i n=${#PREPARED_GUESTS[@]}
	for ((i = 0; i < n; i++)); do
		seen="${PREPARED_GUESTS[i]}"
		[[ "$seen" == "$guest" ]] && return 0
	done
	PREPARED_GUESTS+=("$guest")
	return 0
}

# copy_payload moves a bootstrap payload from one instance to another through a
# pipe. The secret never touches the operator's disk and never enters a variable.
copy_payload() {
	local src="$1" src_path="$2" dst="$3" dst_path="$4"
	"$INCUS_BIN" file pull "$(target "$src")$src_path" - --project "$PROJECT" |
		"$INCUS_BIN" file push - "$(target "$dst")$dst_path" --project "$PROJECT" --mode 0600 >/dev/null
}

# --- Guest dependency preflight -----------------------------------------------

# guest_missing_deps prints the GUEST_DEPS binaries absent from a guest.
guest_missing_deps() {
	local guest="$1" dep missing=""
	for dep in $GUEST_DEPS; do
		if ! "$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
			sh -c 'command -v "$1" >/dev/null 2>&1' sh "$dep" >/dev/null 2>&1; then
			missing="${missing:+$missing }$dep"
		fi
	done
	printf '%s' "$missing"
}

# ensure_guest_deps returns 0 when every dependency is present, installing the
# missing ones only under the explicit GUEST_INSTALL_DEPS=1 opt-in. On failure it
# leaves the exact missing list in GUEST_PROBLEM.
ensure_guest_deps() {
	local guest="$1" missing
	missing=$(guest_missing_deps "$guest")
	if [[ -z "$missing" ]]; then
		log "deps: $guest has $GUEST_DEPS"
		return 0
	fi

	if [[ "$GUEST_INSTALL_DEPS" != "1" ]]; then
		GUEST_PROBLEM="is missing guest dependencies: $missing (install them, or set GUEST_INSTALL_DEPS=1 to let this harness run '$GUEST_INSTALL_CMD $missing' inside the guest)"
		log "deps: $guest $GUEST_PROBLEM"
		return 1
	fi

	log "deps: GUEST_INSTALL_DEPS=1 — installing '$missing' in $guest. This MUTATES the guest;"
	log "deps: record it in the evidence inventory."
	if ! "$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
		sh -c "$GUEST_INSTALL_CMD $missing"; then
		GUEST_PROBLEM="is missing guest dependencies: $missing (GUEST_INSTALL_CMD failed inside the guest)"
		log "deps: $guest $GUEST_PROBLEM"
		return 1
	fi

	missing=$(guest_missing_deps "$guest")
	if [[ -n "$missing" ]]; then
		GUEST_PROBLEM="is still missing guest dependencies after GUEST_INSTALL_CMD: $missing"
		log "deps: $guest $GUEST_PROBLEM"
		return 1
	fi
	log "deps: $guest now has $GUEST_DEPS"
	return 0
}

# assess_guest decides once whether a guest can carry a case at all: it exists,
# its guest API socket is up, it has the harness dependencies, and the harness
# stages into it. It fills GUEST_PROBLEM with a description, empty when usable.
assess_guest() {
	local guest="$1"
	GUEST_PROBLEM=""

	if ! instance_exists "$guest"; then
		GUEST_PROBLEM="does not exist in project $PROJECT on remote '${INCUS_REMOTE:-local}'"
		return 1
	fi
	if ! wait_for_guest "$guest"; then
		GUEST_PROBLEM="never exposed /dev/incus/sock within ${GUEST_READY_TIMEOUT}s (container: security.guestapi must not be false; VM: incus-agent must be running)"
		return 1
	fi
	ensure_guest_deps "$guest" || return 1
	if ! prepare_guest "$guest"; then
		GUEST_PROBLEM="could not be staged: pushing guest-bootstrap.sh into $GUEST_STAGE_DIR failed"
		return 1
	fi
	return 0
}

# guest_problem returns the cached assessment, running it on first use. It sets
# GUEST_PROBLEM and returns non-zero when the guest is unusable.
guest_problem() {
	local guest="$1" i n=${#DEP_GUEST[@]}
	for ((i = 0; i < n; i++)); do
		if [[ "${DEP_GUEST[i]}" == "$guest" ]]; then
			GUEST_PROBLEM="${DEP_STATE[i]}"
			[[ -z "$GUEST_PROBLEM" ]]
			return $?
		fi
	done

	step "assessing guest $guest"
	assess_guest "$guest" || true
	DEP_GUEST+=("$guest")
	DEP_STATE+=("$GUEST_PROBLEM")
	[[ -z "$GUEST_PROBLEM" ]]
}

# require_guests records an ERROR for the case and returns non-zero when any
# named guest cannot carry it. This is the gate that keeps a missing jq out of
# the PASS column.
require_guests() {
	local name="$1"
	shift
	local guest ok=0
	for guest in "$@"; do
		if ! guest_problem "$guest"; then
			case_error "$name" "precondition: $guest $GUEST_PROBLEM"
			ok=1
		fi
	done
	((ok == 0))
}

# --- Harness invocation -------------------------------------------------------

# run_guest executes guest-bootstrap.sh inside an instance with the shared broker
# environment plus the per-case variables given as VAR=VALUE arguments. It sets
# GUEST_OUT and GUEST_RC and echoes the guest transcript, indented.
run_guest() {
	local guest="$1"
	shift
	set +e
	GUEST_OUT=$("$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
		env ${GUEST_ENV[@]+"${GUEST_ENV[@]}"} "$@" "$GUEST_SCRIPT_IN_GUEST" 2>&1)
	GUEST_RC=$?
	set -e
	printf '%s\n' "$GUEST_OUT" | sed -e "s/^/    [$guest] /"
}

# result_field reads one key from the RESULT line of a captured transcript. The
# harness emits only space-free values, so a plain scan is sufficient.
result_field() {
	local text="$1" key="$2"
	awk -v want="$key" '
		$1 == "RESULT" {
			for (i = 2; i <= NF; i++) {
				eq = index($i, "=")
				if (eq > 0 && substr($i, 1, eq - 1) == want) {
					value = substr($i, eq + 1)
				}
			}
		}
		END { print value }
	' <<<"$text"
}

# epoch_of converts an RFC3339 instant to Unix seconds with whichever date(1) is
# present: the GNU spelling first, then the BSD one. The output is validated
# rather than trusted, because BSD date reads -d as a DST flag and can answer
# something that is not an epoch at all. It fails quietly when neither parses.
epoch_of() {
	local ts="${1:-}" out=""
	[[ -n "$ts" ]] || return 1
	ts="${ts%Z}"
	ts="${ts%%.*}"
	[[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || return 1
	out=$(date -u -d "${ts}Z" +%s 2>/dev/null || true)
	if [[ ! "$out" =~ ^[0-9]+$ ]]; then
		out=$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "$ts" +%s 2>/dev/null || true)
	fi
	[[ "$out" =~ ^[0-9]+$ ]] || return 1
	printf '%s' "$out"
}

# mint asks the broker for a nonce. $1 is the instance UUID, $2 an optional TTL
# override in seconds. Sets MINT_RC and the MINT_* fields.
mint() {
	local uuid="$1" ttl="${2:-$MINT_TTL_SECONDS}"
	MINT_NONCE_ID=""
	MINT_EXPIRES_AT=""
	MINT_INSTANCE_NAME=""
	MINT_GENERATION=""
	set +e
	MINT_OUT=$(MINT_TTL_SECONDS="$ttl" "$MINT_SCRIPT" "$uuid" "$PROJECT" 2>&1)
	MINT_RC=$?
	set -e
	printf '%s\n' "$MINT_OUT" | sed -e 's/^/    [mint] /'
	MINT_NONCE_ID=$(result_field "$MINT_OUT" nonce_id)
	MINT_EXPIRES_AT=$(result_field "$MINT_OUT" expires_at)
	MINT_INSTANCE_NAME=$(result_field "$MINT_OUT" instance_name)
	MINT_GENERATION=$(result_field "$MINT_OUT" generation_uuid)
}

# mint_or_error mints and records an ERROR when the mint did not succeed: a mint
# that never happened is a precondition failure, not a lifecycle verdict.
mint_or_error() {
	local name="$1" uuid="$2" ttl="${3:-$MINT_TTL_SECONDS}"
	mint "$uuid" "$ttl"
	if ((MINT_RC != 0)) || [[ -z "$MINT_NONCE_ID" ]]; then
		case_error "$name" "precondition: the mint for instance_uuid=$uuid did not produce a nonce (operator-mint.sh exit $MINT_RC); see the [mint] transcript above"
		return 1
	fi
	log "    minted nonce_id=$MINT_NONCE_ID expires_at=${MINT_EXPIRES_AT:--} instance_name=${MINT_INSTANCE_NAME:--} generation_uuid=${MINT_GENERATION:--}"
	return 0
}

# --- Case bodies --------------------------------------------------------------

# case_a proves the whole intended path: the broker writes the key, the guest
# reads it through its own socket, and the broker grants an identity.
case_a() {
	local name="a"
	section "case $name — positive mint then redeem (P8 step 4)"
	require_guests "$name" "$GUEST_A" || return 0
	clear_key "$GUEST_A" || true
	mint_or_error "$name" "$GUEST_A_UUID" || return 0

	step "guest A reads its own bootstrap key"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/a-payload.json"
	if ((GUEST_RC != 0)); then
		local socket_status reason
		socket_status=$(result_field "$GUEST_OUT" socket_status)
		reason=$(result_field "$GUEST_OUT" reason)
		if [[ "$socket_status" == "404" || "$socket_status" == "403" ]]; then
			fail "$name" "the mint reported success but guest A cannot read $BOOTSTRAP_KEY through /dev/incus/sock (guest API HTTP $socket_status): the key was never delivered"
		else
			case_error "$name" "precondition: guest A's socket read did not complete (exit $GUEST_RC, guest API HTTP ${socket_status:-none}, reason=${reason:--})"
		fi
		return 0
	fi
	local read_id
	read_id=$(result_field "$GUEST_OUT" nonce_id)
	if [[ "$read_id" != "$MINT_NONCE_ID" ]]; then
		fail "$name" "guest A read nonce_id=$read_id but the broker minted $MINT_NONCE_ID"
		return 0
	fi

	step "guest A redeems through its own socket"
	run_guest "$GUEST_A" MODE=redeem
	local status uuid name_resolved selectors reason
	status=$(result_field "$GUEST_OUT" status)
	uuid=$(result_field "$GUEST_OUT" instance_uuid)
	name_resolved=$(result_field "$GUEST_OUT" instance_name)
	selectors=$(result_field "$GUEST_OUT" selectors)
	reason=$(result_field "$GUEST_OUT" reason)
	if ((GUEST_RC != 0)); then
		if [[ "$(rejection_kind "$status" "$reason")" == "decision" ]]; then
			fail "$name" "the broker REFUSED a fresh, correctly delivered nonce ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
		else
			case_error "$name" "no decision was observed: the redemption never reached a verdict ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
		fi
		return 0
	fi
	if [[ -z "$uuid" || "$uuid" == "-" ]]; then
		case_error "$name" "granted HTTP $status but the response carried no resolved instance_uuid, so the binding was not observed"
		return 0
	fi
	if [[ "$uuid" != "$GUEST_A_UUID" ]]; then
		fail "$name" "granted, but the broker resolved instance_uuid=$uuid instead of A's $GUEST_A_UUID"
		return 0
	fi
	if [[ -n "$name_resolved" && "$name_resolved" != "-" && "$name_resolved" != "$GUEST_A" ]]; then
		fail "$name" "granted, but the broker resolved instance_name=$name_resolved instead of $GUEST_A; P6 makes names reusable, so the write target must re-resolve to A"
		return 0
	fi
	pass "$name" "guest A redeemed its own nonce ($MINT_NONCE_ID) through /dev/incus/sock, HTTP $status, instance_uuid=$uuid, selectors=${selectors:--}"
	expect_status "$name" 200 "$status"

	step "the broker should have cleared the key after consuming it"
	run_guest "$GUEST_A" MODE=fetch
	if ((GUEST_RC == 0)); then
		note "$name" "$BOOTSTRAP_KEY is still readable after consumption. P8 step 3 commits used=true before"
		note "$name" "clearing the key, so a lingering consumed value is harmless, not reusable — case b proves that."
	else
		log "    key cleared: the guest read now fails, as designed"
	fi
}

# case_b proves single use for a sequential second attempt.
case_b() {
	local name="b"
	section "case $name — second redemption of the same nonce is rejected (P8 step 4)"
	require_guests "$name" "$GUEST_A" || return 0
	clear_key "$GUEST_A" || true
	mint_or_error "$name" "$GUEST_A_UUID" || return 0

	step "stage the payload inside guest A, then redeem once"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/b-payload.json"
	if ((GUEST_RC != 0)); then
		case_error "$name" "precondition: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	run_guest "$GUEST_A" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/b-payload.json"
	if ((GUEST_RC != 0)); then
		case_error "$name" "precondition: the FIRST redemption did not succeed, so reuse cannot be measured (exit $GUEST_RC, HTTP $(result_field "$GUEST_OUT" status))"
		return 0
	fi

	step "redeem the very same nonce a second time"
	run_guest "$GUEST_A" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/b-payload.json"
	local status reason
	status=$(result_field "$GUEST_OUT" status)
	reason=$(result_field "$GUEST_OUT" reason)
	if ((GUEST_RC == 0)); then
		fail "$name" "the same nonce was redeemed TWICE (HTTP $status): single use is not enforced"
		return 0
	fi
	if [[ "$(rejection_kind "$status" "$reason")" != "decision" ]]; then
		case_error "$name" "the second redemption failed without a broker decision, so single use was not proven ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
		return 0
	fi
	pass "$name" "the second redemption of $MINT_NONCE_ID was rejected with HTTP $status"
	expect_status "$name" 409 "$status"
}

# case_c proves expiry. The guest still holds a readable key; only the
# server-side record has aged out.
case_c() {
	local name="c"
	section "case $name — expired nonce is rejected (P8 step 4)"
	require_guests "$name" "$GUEST_A" || return 0
	clear_key "$GUEST_A" || true
	mint_or_error "$name" "$GUEST_A_UUID" "$SHORT_TTL_SECONDS" || return 0

	# ttl_seconds is bounded by the broker, so the returned expires_at — not the
	# requested TTL — decides how long this case has to wait.
	local wait_for="" basis=""
	if [[ -n "$EXPIRY_WAIT_SECONDS" ]]; then
		wait_for="$EXPIRY_WAIT_SECONDS"
		basis="EXPIRY_WAIT_SECONDS"
	else
		local expires_epoch now remaining
		if expires_epoch=$(epoch_of "$MINT_EXPIRES_AT"); then
			now=$(date -u +%s)
			remaining=$((expires_epoch - now))
			wait_for=$((remaining + 3))
			((wait_for < 1)) && wait_for=1
			basis="the broker's expires_at (${remaining}s of TTL left)"
			if ((remaining > SHORT_TTL_SECONDS + 5)); then
				note "$name" "the broker returned ${remaining}s of TTL for a ttl_seconds=$SHORT_TTL_SECONDS request. It should honour a valid ttl_seconds exactly and refuse an invalid one with 400, so this is a contract difference worth recording. Waiting for the applied expiry."
			fi
		else
			wait_for=$((SHORT_TTL_SECONDS + 3))
			basis="SHORT_TTL_SECONDS+3 (expires_at=${MINT_EXPIRES_AT:--} could not be parsed)"
			note "$name" "could not parse expires_at, so the wait is a guess; set EXPIRY_WAIT_SECONDS if this case errors."
		fi
	fi

	if ((wait_for > MAX_EXPIRY_WAIT_SECONDS)); then
		case_error "$name" "expiry would take ${wait_for}s (basis: $basis), above MAX_EXPIRY_WAIT_SECONDS=$MAX_EXPIRY_WAIT_SECONDS. The broker did not honour ttl_seconds=$SHORT_TTL_SECONDS: lower its -nonce-ttl, or raise MAX_EXPIRY_WAIT_SECONDS to wait it out."
		return 0
	fi

	step "waiting ${wait_for}s for the nonce to expire (basis: $basis, expires_at=${MINT_EXPIRES_AT:--})"
	sleep "$wait_for"

	step "redeem after expiry"
	run_guest "$GUEST_A" MODE=redeem
	local status reason
	status=$(result_field "$GUEST_OUT" status)
	reason=$(result_field "$GUEST_OUT" reason)
	if ((GUEST_RC == 0)); then
		fail "$name" "an expired nonce was still redeemed (HTTP $status): expiry is not enforced"
		return 0
	fi
	if [[ "$(rejection_kind "$status" "$reason")" != "decision" ]]; then
		case_error "$name" "the post-expiry redemption failed without a broker decision, so expiry was not measured ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
		return 0
	fi
	pass "$name" "the expired nonce $MINT_NONCE_ID was rejected with HTTP $status after ${wait_for}s"
	expect_status "$name" 409 "$status"
}

# case_d proves the atomic consume: two simultaneous redemptions of one nonce,
# exactly one success. Both run inside guest A against one staged payload.
case_d() {
	local name="d"
	section "case $name — two CONCURRENT redemptions yield exactly one success (P8 step 4)"
	require_guests "$name" "$GUEST_A" || return 0
	clear_key "$GUEST_A" || true
	mint_or_error "$name" "$GUEST_A_UUID" || return 0

	step "stage the payload inside guest A"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/d-payload.json"
	if ((GUEST_RC != 0)); then
		case_error "$name" "precondition: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi

	step "fire both redemptions as background jobs"
	local out1 out2 rc1 rc2
	out1=$(mktemp)
	out2=$(mktemp)
	set +e
	"$INCUS_BIN" exec "$(target "$GUEST_A")" --project "$PROJECT" -- \
		env ${GUEST_ENV[@]+"${GUEST_ENV[@]}"} MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/d-payload.json" \
		"$GUEST_SCRIPT_IN_GUEST" >"$out1" 2>&1 &
	local pid1=$!
	"$INCUS_BIN" exec "$(target "$GUEST_A")" --project "$PROJECT" -- \
		env ${GUEST_ENV[@]+"${GUEST_ENV[@]}"} MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/d-payload.json" \
		"$GUEST_SCRIPT_IN_GUEST" >"$out2" 2>&1 &
	local pid2=$!
	wait "$pid1"
	rc1=$?
	wait "$pid2"
	rc2=$?
	set -e

	sed -e 's/^/    [A#1] /' "$out1"
	sed -e 's/^/    [A#2] /' "$out2"
	local text1 text2 status1 status2 reason1 reason2
	text1=$(cat "$out1")
	text2=$(cat "$out2")
	status1=$(result_field "$text1" status)
	status2=$(result_field "$text2" status)
	reason1=$(result_field "$text1" reason)
	reason2=$(result_field "$text2" reason)
	rm -f -- "$out1" "$out2"

	local successes=0
	# Plain if blocks, not `&& ((n++))`: an arithmetic command whose result is
	# zero returns status 1, and under set -e that would abort the case.
	if ((rc1 == 0)); then successes=$((successes + 1)); fi
	if ((rc2 == 0)); then successes=$((successes + 1)); fi
	log "    attempt 1: exit $rc1 HTTP ${status1:-none} reason=${reason1:--}"
	log "    attempt 2: exit $rc2 HTTP ${status2:-none} reason=${reason2:--}"

	case "$successes" in
	1)
		local loser_status="$status1" loser_reason="$reason1" loser_rc="$rc1"
		if ((rc1 == 0)); then
			loser_status="$status2"
			loser_reason="$reason2"
			loser_rc="$rc2"
		fi
		if [[ "$(rejection_kind "$loser_status" "$loser_reason")" != "decision" ]]; then
			case_error "$name" "one redemption succeeded but the other never reached a broker decision ($(reject_detail "$loser_rc" "$loser_status" "$loser_reason")), so the atomic consume was not proven"
			return 0
		fi
		pass "$name" "exactly one of two concurrent redemptions of $MINT_NONCE_ID succeeded (HTTP $status1 / $status2)"
		expect_status "$name" 409 "$loser_status"
		;;
	0)
		if [[ "$(rejection_kind "$status1" "$reason1")" != "decision" && "$(rejection_kind "$status2" "$reason2")" != "decision" ]]; then
			case_error "$name" "neither concurrent redemption reached a broker decision (HTTP ${status1:-none} / ${status2:-none}): the concurrency behaviour was not measured"
		else
			fail "$name" "both concurrent redemptions were rejected (HTTP ${status1:-none} / ${status2:-none}): the nonce was consumed by neither"
		fi
		;;
	*)
		fail "$name" "BOTH concurrent redemptions succeeded (HTTP $status1 / $status2): the consume is not atomic"
		;;
	esac
}

# case_e proves a nonce cannot outlive its instance. P6: names are reusable after
# delete+recreate, so the broker must re-resolve the UUID at redemption; once the
# instance is gone there is nothing to resolve.
case_e() {
	local name="e"
	section "case $name — nonce for a DELETED instance is rejected (P8 step 4)"
	require_guests "$name" "$GUEST_B" || return 0

	if instance_exists "$TMP_INSTANCE"; then
		step "removing a leftover $TMP_INSTANCE first"
		if ! "$INCUS_BIN" delete "$(target "$TMP_INSTANCE")" --project "$PROJECT" --force >/dev/null; then
			case_error "$name" "precondition: a leftover $TMP_INSTANCE exists and could not be deleted"
			return 0
		fi
	fi

	step "creating the disposable instance $TMP_INSTANCE ($TMP_TYPE, $TMP_IMAGE)"
	local -a launch=(launch "$TMP_IMAGE" "$(target "$TMP_INSTANCE")" --project "$PROJECT")
	[[ "$TMP_TYPE" == "vm" ]] && launch+=(--vm)
	if ! "$INCUS_BIN" "${launch[@]}" >/dev/null; then
		case_error "$name" "precondition: could not launch $TMP_INSTANCE from $TMP_IMAGE"
		return 0
	fi
	TMP_CREATED=1
	register_touched "$TMP_INSTANCE"

	# The stock images:debian/13 rootfs has no jq, which is exactly how this case
	# was lost in the P8 live run. It is a dependency ERROR, never a PASS.
	require_guests "$name" "$TMP_INSTANCE" || return 0

	local tmp_uuid
	tmp_uuid=$(config_get "$TMP_INSTANCE" volatile.uuid)
	if [[ -z "$tmp_uuid" ]]; then
		case_error "$name" "precondition: could not read volatile.uuid of $TMP_INSTANCE"
		return 0
	fi
	log "    $TMP_INSTANCE volatile.uuid=$tmp_uuid"

	mint_or_error "$name" "$tmp_uuid" || return 0

	step "stage the payload inside the disposable instance, then pipe it into guest B"
	run_guest "$TMP_INSTANCE" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/e-payload.json"
	if ((GUEST_RC != 0)); then
		case_error "$name" "precondition: $TMP_INSTANCE could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	if ! copy_payload "$TMP_INSTANCE" "$GUEST_STAGE_DIR/e-payload.json" "$GUEST_B" "$GUEST_STAGE_DIR/e-payload.json"; then
		case_error "$name" "precondition: could not move the payload from $TMP_INSTANCE into $GUEST_B"
		return 0
	fi

	step "deleting $TMP_INSTANCE, then redeeming its still-unused nonce from guest B"
	if ! "$INCUS_BIN" delete "$(target "$TMP_INSTANCE")" --project "$PROJECT" --force >/dev/null; then
		case_error "$name" "precondition: could not delete $TMP_INSTANCE, so the deleted-instance state was never reached"
		return 0
	fi
	TMP_CREATED=0

	run_guest "$GUEST_B" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/e-payload.json"
	local status reason
	status=$(result_field "$GUEST_OUT" status)
	reason=$(result_field "$GUEST_OUT" reason)
	if ((GUEST_RC == 0)); then
		fail "$name" "a nonce bound to a DELETED instance was redeemed (HTTP $status)"
		return 0
	fi
	if [[ "$(rejection_kind "$status" "$reason")" != "decision" ]]; then
		case_error "$name" "the redemption failed without a broker decision, so deletion invalidation was not measured ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
		return 0
	fi
	pass "$name" "the nonce of the deleted $TMP_INSTANCE ($tmp_uuid) was rejected with HTTP $status"
	expect_status "$name" 409 "$status"
}

# case_f proves generation invalidation. P6 proved a snapshot restore always
# installs a fresh volatile.uuid.generation, which is the rollback discriminator.
case_f() {
	local name="f"
	section "case $name — nonce invalidated when volatile.uuid.generation changes (P8 step 4)"
	require_guests "$name" "$GUEST_A" "$GUEST_B" || return 0
	clear_key "$GUEST_A" || true
	mint_or_error "$name" "$GUEST_A_UUID" || return 0

	local gen_before
	gen_before=$(config_get "$GUEST_A" volatile.uuid.generation)
	log "    generation before: ${gen_before:-<absent>}"

	step "stage the payload, then stash it in guest B so it survives the restore"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/f-payload.json"
	if ((GUEST_RC != 0)); then
		case_error "$name" "precondition: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	if ! copy_payload "$GUEST_A" "$GUEST_STAGE_DIR/f-payload.json" "$GUEST_B" "$GUEST_STAGE_DIR/f-payload.json"; then
		case_error "$name" "precondition: could not stash the payload in $GUEST_B before the restore"
		return 0
	fi

	local snapshot="p8-generation-$$"
	step "snapshot and restore guest A as $snapshot"
	if ! "$INCUS_BIN" snapshot create "$(target "$GUEST_A")" "$snapshot" --project "$PROJECT" >/dev/null; then
		case_error "$name" "precondition: could not snapshot $GUEST_A as $snapshot"
		return 0
	fi
	SNAPSHOTS_CREATED+=("$GUEST_A $snapshot")
	if ! "$INCUS_BIN" stop "$(target "$GUEST_A")" --project "$PROJECT" >/dev/null; then
		case_error "$name" "precondition: could not stop $GUEST_A for the restore"
		return 0
	fi
	if ! "$INCUS_BIN" snapshot restore "$(target "$GUEST_A")" "$snapshot" --project "$PROJECT" >/dev/null; then
		case_error "$name" "precondition: could not restore $GUEST_A from $snapshot"
		return 0
	fi
	if ! "$INCUS_BIN" start "$(target "$GUEST_A")" --project "$PROJECT" >/dev/null; then
		case_error "$name" "precondition: could not start $GUEST_A after the restore"
		return 0
	fi
	if ! wait_for_guest "$GUEST_A"; then
		case_error "$name" "precondition: guest A did not come back after the restore within ${GUEST_READY_TIMEOUT}s"
		return 0
	fi
	# The restore reverted the filesystem, so the staging directory is gone.
	if ! prepare_guest "$GUEST_A"; then
		case_error "$name" "precondition: could not re-stage the harness in $GUEST_A after the restore"
		return 0
	fi

	local gen_after
	gen_after=$(config_get "$GUEST_A" volatile.uuid.generation)
	log "    generation after:  ${gen_after:-<absent>}"
	if [[ -z "$gen_after" || "$gen_after" == "$gen_before" ]]; then
		case_error "$name" "precondition: the restore did not install a fresh generation (before=${gen_before:--} after=${gen_after:--}), contradicting P6; invalidation cannot be measured"
		return 0
	fi

	step "pipe the pre-restore payload back into guest A and redeem it"
	if ! copy_payload "$GUEST_B" "$GUEST_STAGE_DIR/f-payload.json" "$GUEST_A" "$GUEST_STAGE_DIR/f-payload.json"; then
		case_error "$name" "precondition: could not move the stashed payload back into $GUEST_A"
		return 0
	fi
	run_guest "$GUEST_A" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/f-payload.json"
	local status reason
	status=$(result_field "$GUEST_OUT" status)
	reason=$(result_field "$GUEST_OUT" reason)
	if ((GUEST_RC == 0)); then
		fail "$name" "a nonce minted against generation $gen_before was redeemed after the generation became $gen_after (HTTP $status)"
		return 0
	fi
	if [[ "$(rejection_kind "$status" "$reason")" != "decision" ]]; then
		case_error "$name" "the redemption failed without a broker decision, so generation invalidation was not measured ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
		return 0
	fi
	pass "$name" "the generation change ($gen_before -> $gen_after) invalidated the nonce; HTTP $status"
	expect_status "$name" 409 "$status"
}

# case_g proves the delivery channel is per-instance: B's own socket exposes only
# B's configuration, so A's nonce is not reachable from B.
case_g() {
	local name="g"
	section "case $name — guest B cannot read A's nonce through its own socket (P8 step 5)"
	require_guests "$name" "$GUEST_A" "$GUEST_B" || return 0
	clear_key "$GUEST_A" || true
	clear_key "$GUEST_B" || true
	mint_or_error "$name" "$GUEST_A_UUID" || return 0

	step "guest A reads its key, for the digest to compare against"
	run_guest "$GUEST_A" MODE=fetch
	if ((GUEST_RC != 0)); then
		case_error "$name" "precondition: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	local a_digest
	a_digest=$(result_field "$GUEST_OUT" payload_sha256)
	log "    A payload sha256=$a_digest (digests are permitted in evidence; values are not)"

	step "guest B attempts the same read through its own /dev/incus/sock"
	run_guest "$GUEST_B" MODE=fetch
	local socket_status b_digest reason
	socket_status=$(result_field "$GUEST_OUT" socket_status)
	b_digest=$(result_field "$GUEST_OUT" payload_sha256)
	reason=$(result_field "$GUEST_OUT" reason)

	if ((GUEST_RC != 0)); then
		# Only the guest API's own refusal proves isolation. A transport failure,
		# a missing binary or a dead socket proves nothing at all.
		case "$socket_status" in
		404 | 403)
			pass "$name" "guest B's socket refused $BOOTSTRAP_KEY with guest API HTTP $socket_status; A's nonce is unreachable from B"
			expect_status "$name" 404 "$socket_status"
			;;
		*)
			case_error "$name" "guest B's read failed without a guest API refusal (exit $GUEST_RC, guest API HTTP ${socket_status:-none}, reason=${reason:--}): isolation was not proven"
			;;
		esac
		return 0
	fi

	if [[ -n "$b_digest" && "$b_digest" == "$a_digest" ]]; then
		fail "$name" "guest B read A's exact bootstrap payload (matching sha256=$b_digest): the delivery channel is not per-instance"
	else
		fail "$name" "guest B read a bootstrap value of its own (sha256=$b_digest) although no nonce was minted for it"
	fi
}

# case_h proves the claimed UUID is untrusted input: B presents B's own nonce and
# asks for A's identity. The security property is that B never obtains A, and the
# broker may deliver it two ways:
#
#   * it accepts the extra field and IGNORES it, resolving only B (what
#     SPIKE_PLAN.md P8 step 5 describes); or
#   * its strict decoder REFUSES the whole request with 400, so a caller-claimed
#     identity is not merely ignored but not accepted at all.
#
# Both pass, and the refusal is the stronger of the two. A 400 alone is not the
# whole story though: it must not mean that B's own nonce has stopped working, so
# the case follows up by redeeming the same nonce without the claim and requires
# B, and only B, to come back.
case_h() {
	local name="h"
	section "case $name — guest B claims A's UUID with B's own nonce (P8 step 5)"
	require_guests "$name" "$GUEST_B" || return 0
	clear_key "$GUEST_A" || true
	clear_key "$GUEST_B" || true
	mint_or_error "$name" "$GUEST_B_UUID" || return 0

	step "guest B redeems its own nonce while claiming instance_uuid=$GUEST_A_UUID"
	run_guest "$GUEST_B" MODE=redeem CLAIM_UUID="$GUEST_A_UUID"
	local status uuid name_resolved spiffe_id selectors reason claim_refused=0
	status=$(result_field "$GUEST_OUT" status)
	uuid=$(result_field "$GUEST_OUT" instance_uuid)
	name_resolved=$(result_field "$GUEST_OUT" instance_name)
	spiffe_id=$(result_field "$GUEST_OUT" spiffe_id)
	selectors=$(result_field "$GUEST_OUT" selectors)
	reason=$(result_field "$GUEST_OUT" reason)

	if ((GUEST_RC != 0)); then
		if [[ "$status" != "400" ]]; then
			# 401/409/5xx/000 say nothing about the claim: they say the nonce
			# path itself did not work, so nothing was observed.
			case_error "$name" "the redemption failed for a reason unrelated to the claim ($(reject_detail "$GUEST_RC" "$status" "$reason")): the claim was never judged"
			return 0
		fi
		claim_refused=1
		note "$name" "the broker REFUSED the caller-supplied instance_uuid with HTTP 400 instead of ignoring it. SPIKE_PLAN.md"
		note "$name" "expects the claim to be ignored; refusing it outright is stricter and also acceptable, as long as"
		note "$name" "B's own nonce still resolves B — which the follow-up below requires."

		step "redeem the same nonce again WITHOUT the claim: B must still get B"
		run_guest "$GUEST_B" MODE=redeem
		status=$(result_field "$GUEST_OUT" status)
		uuid=$(result_field "$GUEST_OUT" instance_uuid)
		name_resolved=$(result_field "$GUEST_OUT" instance_name)
		spiffe_id=$(result_field "$GUEST_OUT" spiffe_id)
		selectors=$(result_field "$GUEST_OUT" selectors)
		reason=$(result_field "$GUEST_OUT" reason)
		if ((GUEST_RC != 0)); then
			case_error "$name" "the claim was refused with HTTP 400, but B's own unclaimed nonce then failed too ($(reject_detail "$GUEST_RC" "$status" "$reason")): the harness cannot tell a refused claim from a broken redemption"
			return 0
		fi
	fi

	if [[ "$uuid" == "$GUEST_A_UUID" || "$name_resolved" == "$GUEST_A" ]]; then
		fail "$name" "B obtained A's identity: the broker honoured the claimed UUID (instance_uuid=$uuid, instance_name=$name_resolved)"
		return 0
	fi
	if [[ -n "$spiffe_id" && "$spiffe_id" != "-" && "$spiffe_id" == *"$GUEST_A"* ]]; then
		fail "$name" "B received a SPIFFE ID naming A ($spiffe_id) despite presenting B's nonce"
		return 0
	fi
	if [[ -n "$selectors" && "$selectors" != "-" && "$selectors" == *"$GUEST_A_UUID"* ]]; then
		fail "$name" "B received selectors carrying A's UUID ($selectors)"
		return 0
	fi
	if [[ -z "$uuid" || "$uuid" == "-" ]]; then
		case_error "$name" "granted HTTP $status but with no resolved instance_uuid, so the harness cannot say whose identity B received"
		return 0
	fi
	if [[ "$uuid" != "$GUEST_B_UUID" ]]; then
		fail "$name" "B received an identity for neither A nor B (instance_uuid=$uuid)"
		return 0
	fi
	if ((claim_refused)); then
		pass "$name" "the claimed UUID was REFUSED outright (HTTP 400) and B's own nonce still resolved only B (instance_uuid=$uuid, instance_name=${name_resolved:--}, selectors=${selectors:--})"
	else
		pass "$name" "the claimed UUID was ignored; the broker resolved only B (instance_uuid=$uuid, instance_name=${name_resolved:--}, selectors=${selectors:--})"
	fi
	expect_status "$name" 200 "$status"
}

# case_i is a MEASUREMENT of a known limitation, not a pass/fail case.
#
# SPIKE_PLAN.md P8 step 5: "A deliberately leaked, unused A nonce is a bearer
# credential and can impersonate A unless the prototype adds another
# caller-binding mechanism; measure and record that limitation instead of
# expecting rejection." GUEST_SOCK_BRIEF.md section 6 says the same thing from
# the guest side: a guest cannot learn its own UUID or generation, so possession
# of the payload is the only proof it can present. This case therefore records
# what happens, and neither a success nor a rejection changes the exit status.
# Only failing to measure it at all is an ERROR: an unmeasured case i leaves the
# P8 go/no-go record incomplete.
case_i() {
	local name="i"
	section "case $name — MEASURING A KNOWN LIMITATION: leaked unused A nonce used from B (P8 step 5)"
	log "This case is expected to SUCCEED. An unused nonce is a bearer credential; a success here is"
	log "the recorded bearer-token risk and a go/no-go input, not a bug and not a run failure."
	require_guests "$name" "$GUEST_A" "$GUEST_B" || return 0
	clear_key "$GUEST_A" || true
	mint "$GUEST_A_UUID" "$MINT_TTL_SECONDS"
	if ((MINT_RC != 0)) || [[ -z "$MINT_NONCE_ID" ]]; then
		case_error "$name" "NOT MEASURED: the mint for A failed (operator-mint.sh exit $MINT_RC)"
		return 0
	fi

	step "stage A's payload, then pipe it into guest B — the deliberate leak"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/i-payload.json"
	if ((GUEST_RC != 0)); then
		case_error "$name" "NOT MEASURED: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	if ! copy_payload "$GUEST_A" "$GUEST_STAGE_DIR/i-payload.json" "$GUEST_B" "$GUEST_STAGE_DIR/i-payload.json"; then
		case_error "$name" "NOT MEASURED: could not move A's payload into $GUEST_B"
		return 0
	fi

	step "guest B redeems A's unused nonce"
	run_guest "$GUEST_B" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/i-payload.json"
	local status uuid name_resolved spiffe_id selectors reason
	status=$(result_field "$GUEST_OUT" status)
	uuid=$(result_field "$GUEST_OUT" instance_uuid)
	name_resolved=$(result_field "$GUEST_OUT" instance_name)
	spiffe_id=$(result_field "$GUEST_OUT" spiffe_id)
	selectors=$(result_field "$GUEST_OUT" selectors)
	reason=$(result_field "$GUEST_OUT" reason)

	if ((GUEST_RC != 0)); then
		if [[ "$(rejection_kind "$status" "$reason")" != "decision" ]]; then
			case_error "$name" "NOT MEASURED: the redemption never reached a broker decision ($(reject_detail "$GUEST_RC" "$status" "$reason"))"
			return 0
		fi
		measured "$name" "the leaked unused nonce was REJECTED from B (HTTP $status). The prototype binds the caller by something beyond possession; record what, because SPIKE_PLAN.md expected a success."
		return 0
	fi
	if [[ "$uuid" == "$GUEST_A_UUID" || "$name_resolved" == "$GUEST_A" || "$spiffe_id" == *"$GUEST_A"* ]]; then
		measured "$name" "CONFIRMED bearer-token risk: B redeemed A's leaked nonce and received A's identity (instance_uuid=${uuid:--}, instance_name=${name_resolved:--}, selectors=${selectors:--}, HTTP $status). Expected per SPIKE_PLAN.md P8 step 5; go/no-go input."
		return 0
	fi
	measured "$name" "the leaked nonce was accepted from B but resolved to instance_uuid=${uuid:--} / instance_name=${name_resolved:--} rather than A (HTTP $status): possession alone did not transfer A's identity."
}

# --- Cleanup ------------------------------------------------------------------

cleanup_failed() {
	printf 'cleanup: FAILED — %s\n' "$*" >&2
	CLEANUP_FAILURES+=("$*")
}

# clear_key_verified clears the bootstrap key and then PROVES it is gone by
# reading it back. The value is never captured and never printed: `incus config
# get` is piped straight into `grep -q`, which only reports whether anything is
# there (Appendix D rule 1). PIPESTATUS separates "the key is still set" from "the
# read itself failed", because those need different reports.
clear_key_verified() {
	local guest="$1"
	if ! instance_exists "$guest"; then
		log "cleanup: $guest no longer exists; its config went with it"
		return 0
	fi

	local unset_ok=1
	"$INCUS_BIN" config unset "$(target "$guest")" "$BOOTSTRAP_KEY" --project "$PROJECT" >/dev/null 2>&1 || unset_ok=0

	local get_rc grep_rc
	local -a rcs=()
	set +e
	"$INCUS_BIN" config get "$(target "$guest")" "$BOOTSTRAP_KEY" --project "$PROJECT" 2>/dev/null |
		grep -q '[^[:space:]]'
	# One capture: any later command, an assignment included, replaces PIPESTATUS.
	rcs=("${PIPESTATUS[@]}")
	set -e
	get_rc=${rcs[0]}
	grep_rc=${rcs[1]}

	if ((get_rc != 0)); then
		cleanup_failed "could not read $BOOTSTRAP_KEY back from $guest, so it is UNVERIFIED (unset command $( ((unset_ok)) && printf 'succeeded' || printf 'failed')); clear it by hand"
		return 1
	fi
	if ((grep_rc == 0)); then
		cleanup_failed "$BOOTSTRAP_KEY is STILL SET on $guest — a nonce payload is live in its config; run: $INCUS_BIN config unset $(target "$guest") $BOOTSTRAP_KEY --project $PROJECT"
		return 1
	fi
	log "cleanup: verified $BOOTSTRAP_KEY is absent on $guest"
	return 0
}

# remove_stage_dir deletes a guest staging directory and verifies it is gone.
# Those directories hold raw nonce payloads written by PAYLOAD_OUT.
remove_stage_dir() {
	local guest="$1"
	if ! instance_exists "$guest"; then
		return 0
	fi
	"$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
		rm -rf "$GUEST_STAGE_DIR" >/dev/null 2>&1 || true
	if "$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
		test -e "$GUEST_STAGE_DIR" >/dev/null 2>&1; then
		cleanup_failed "$GUEST_STAGE_DIR still exists in $guest — it holds nonce payload files; remove it by hand"
		return 1
	fi
	log "cleanup: removed $GUEST_STAGE_DIR in $guest (it held nonce payloads)"
	return 0
}

# cleanup runs on every exit, including an abort mid-case. Every step is checked,
# every step is attempted even after an earlier one fails, and an incomplete
# cleanup forces a non-zero exit: P8's rollback requirement is not satisfied by
# trying, only by verifying.
cleanup() {
	local rc=$?
	trap - EXIT
	printf '\n=== cleanup (runs on abort too: P8 requires config keys cleared either way)\n'
	CLEANUP_FAILURES=()

	local i n inst

	# 1. The bootstrap key, on every instance this run may have written to. This
	#    happens even under KEEP_ARTIFACTS: a live nonce is not a debugging aid.
	n=${#TOUCHED_INSTANCES[@]}
	for ((i = 0; i < n; i++)); do
		inst="${TOUCHED_INSTANCES[i]}"
		clear_key_verified "$inst" || true
	done

	# 2. Snapshots this run created.
	n=${#SNAPSHOTS_CREATED[@]}
	if ((n > 0)) && [[ "$KEEP_ARTIFACTS" == "1" ]]; then
		log "cleanup: KEEP_ARTIFACTS=1 — $n snapshot(s) left in place"
	else
		for ((i = 0; i < n; i++)); do
			local pair guest snapshot
			pair="${SNAPSHOTS_CREATED[i]}"
			guest="${pair%% *}"
			snapshot="${pair##* }"
			if instance_exists "$guest" &&
				! "$INCUS_BIN" snapshot delete "$(target "$guest")" "$snapshot" --project "$PROJECT" >/dev/null 2>&1; then
				cleanup_failed "could not delete snapshot $snapshot of $guest"
			else
				log "cleanup: deleted snapshot $snapshot of $guest"
			fi
		done
	fi

	# 3. The disposable instance, when a case left one behind.
	if ((TMP_CREATED)) && instance_exists "$TMP_INSTANCE"; then
		if [[ "$KEEP_ARTIFACTS" == "1" ]]; then
			log "cleanup: KEEP_ARTIFACTS=1 — $TMP_INSTANCE left in place (its bootstrap key was cleared above)"
		elif "$INCUS_BIN" delete "$(target "$TMP_INSTANCE")" --project "$PROJECT" --force >/dev/null 2>&1; then
			TMP_CREATED=0
			log "cleanup: deleted $TMP_INSTANCE"
		else
			cleanup_failed "could not delete the disposable instance $TMP_INSTANCE"
		fi
	fi

	# 4. Guest staging directories, which hold raw payload files.
	n=${#PREPARED_GUESTS[@]}
	if [[ "$KEEP_ARTIFACTS" == "1" ]]; then
		log "cleanup: KEEP_ARTIFACTS=1 — staging directories left in place. They contain NONCE PAYLOADS:"
		log "cleanup:   remove $GUEST_STAGE_DIR inside each guest before capturing evidence."
	else
		for ((i = 0; i < n; i++)); do
			remove_stage_dir "${PREPARED_GUESTS[i]}" || true
		done
	fi

	n=${#CLEANUP_FAILURES[@]}
	if ((n > 0)); then
		log ""
		log "cleanup: INCOMPLETE — $n step(s) failed:"
		for ((i = 0; i < n; i++)); do
			log "  - ${CLEANUP_FAILURES[i]}"
		done
		log "cleanup: a nonce secret or a payload file may still be live. Exit status forced non-zero."
		((rc == 0)) && rc=3
	else
		log "cleanup: complete — every step verified"
	fi

	exit "$rc"
}

# --- Preflight ----------------------------------------------------------------

preflight() {
	[[ -x "$GUEST_SCRIPT" ]] || die "guest-bootstrap.sh is not executable at $GUEST_SCRIPT"
	[[ -x "$MINT_SCRIPT" ]] || die "operator-mint.sh is not executable at $MINT_SCRIPT"
	command -v "$INCUS_BIN" >/dev/null 2>&1 || die "incus client not found: $INCUS_BIN (override with INCUS_BIN)"
	command -v "$CURL_BIN" >/dev/null 2>&1 || die "curl not found on the operator host: $CURL_BIN"
	command -v "$JQ_BIN" >/dev/null 2>&1 || die "jq not found on the operator host: $JQ_BIN"
	command -v "$OPENSSL_BIN" >/dev/null 2>&1 || die "openssl not found on the operator host: $OPENSSL_BIN"

	if [[ -n "$BROKER_CACERT" ]]; then
		[[ -r "$BROKER_CACERT" ]] || die "BROKER_CACERT is not readable: $BROKER_CACERT"
	elif [[ "$ALLOW_INSECURE_TLS" != "1" && -z "$BROKER_FINGERPRINT" ]]; then
		log "NOTE: BROKER_CACERT is unset. The guest still pins the broker by the fingerprint in its"
		log "      payload and uses that leaf as its own anchor, which only works for a self-signed"
		log "      broker certificate. operator-mint.sh needs BROKER_FINGERPRINT or ALLOW_INSECURE_TLS=1."
	fi

	# The mint endpoint is authenticated: without a token every mint answers 401
	# and every case would ERROR for the same uninformative reason. Say so once,
	# here, instead of nine times in the summary.
	if [[ -z "$MINT_AUTH_TOKEN_FILE" && -z "$MINT_AUTH_TOKEN" ]]; then
		die "no operator mint credential: set MINT_AUTH_TOKEN_FILE (preferred) or MINT_AUTH_TOKEN to the token the broker was started with in -mint-token-file. The mint endpoint refuses an unauthenticated caller with 401, so no case could run."
	fi
	if [[ -n "$MINT_AUTH_TOKEN_FILE" ]]; then
		[[ -r "$MINT_AUTH_TOKEN_FILE" ]] || die "MINT_AUTH_TOKEN_FILE is not readable: $MINT_AUTH_TOKEN_FILE"
	fi

	local guest
	for guest in "$GUEST_A" "$GUEST_B"; do
		instance_exists "$guest" || die "instance $guest does not exist in project $PROJECT on remote '${INCUS_REMOTE:-local}'"
		register_touched "$guest"
	done

	[[ -n "$GUEST_A_UUID" ]] || GUEST_A_UUID=$(config_get "$GUEST_A" volatile.uuid)
	[[ -n "$GUEST_B_UUID" ]] || GUEST_B_UUID=$(config_get "$GUEST_B" volatile.uuid)
	[[ -n "$GUEST_A_UUID" ]] || die "could not resolve volatile.uuid of $GUEST_A"
	[[ -n "$GUEST_B_UUID" ]] || die "could not resolve volatile.uuid of $GUEST_B"
	[[ "$GUEST_A_UUID" != "$GUEST_B_UUID" ]] || die "$GUEST_A and $GUEST_B report the same volatile.uuid ($GUEST_A_UUID)"

	GUEST_ENV=(REDEEM_PATH="$REDEEM_PATH" ALLOW_INSECURE_TLS="$ALLOW_INSECURE_TLS" BOOTSTRAP_KEY="$BOOTSTRAP_KEY")
	[[ -n "$GUEST_BROKER_URL" ]] && GUEST_ENV+=(BROKER_URL_OVERRIDE="$GUEST_BROKER_URL")
	[[ -n "$BROKER_TLS_HOSTNAME" ]] && GUEST_ENV+=(BROKER_TLS_HOSTNAME="$BROKER_TLS_HOSTNAME")
	[[ -n "$BROKER_CACERT" ]] && GUEST_ENV+=(BROKER_CACERT="$GUEST_CACERT_IN_GUEST")

	log "remote:            ${INCUS_REMOTE:-<local daemon>}"
	log "project:           $PROJECT"
	log "guest A:           $GUEST_A (volatile.uuid=$GUEST_A_UUID)"
	log "guest B:           $GUEST_B (volatile.uuid=$GUEST_B_UUID)"
	log "broker:            $BROKER_URL (mint $NONCE_PATH, redeem $REDEEM_PATH)"
	log "mint credential:   ${MINT_AUTH_TOKEN_FILE:+file $MINT_AUTH_TOKEN_FILE}${MINT_AUTH_TOKEN_FILE:-from MINT_AUTH_TOKEN} (value never printed)"
	log "bootstrap key:     $BOOTSTRAP_KEY"
	log "guest staging dir: $GUEST_STAGE_DIR"
	log "guest deps:        $GUEST_DEPS (install on demand: GUEST_INSTALL_DEPS=$GUEST_INSTALL_DEPS)"
	log "cases:             $CASES"
	log "strict status:     $STRICT_STATUS"
	log "allow case errors: $ALLOW_CASE_ERRORS"

	# Assess both guests now, so a missing dependency is reported once, before any
	# case runs, instead of surfacing as a mysterious exit code mid-matrix. An
	# unusable guest is not fatal here: each case that needs it records an ERROR.
	local unusable=0
	for guest in "$GUEST_A" "$GUEST_B"; do
		if ! guest_problem "$guest"; then
			log "PREFLIGHT: $guest $GUEST_PROBLEM"
			log "PREFLIGHT: every case needing $guest will be recorded as ERROR, never as PASS."
			unusable=$((unusable + 1))
		fi
	done
	((unusable == 0)) || log "PREFLIGHT: $unusable of 2 guests are unusable."
}

# --- Summary and main ---------------------------------------------------------

# summary prints one row per selected case and decides the exit status.
summary() {
	section "summary"

	local i n=${#CASE_ORDER[@]}
	local passes=0 failures=0 errors=0 measurements=0
	printf '%-6s %-9s %s\n' "case" "outcome" "detail"
	printf '%-6s %-9s %s\n' "----" "-------" "------"
	for ((i = 0; i < n; i++)); do
		local outcome="${CASE_OUTCOME[i]}"
		if [[ "$outcome" == "PENDING" ]]; then
			outcome="ERROR"
			CASE_DETAIL[i]="the case recorded no outcome at all (harness bug); treated as ERROR"
		fi
		printf '%-6s %-9s %s\n' "${CASE_ORDER[i]}" "$outcome" "${CASE_DETAIL[i]}"
		case "$outcome" in
		PASS) passes=$((passes + 1)) ;;
		FAIL) failures=$((failures + 1)) ;;
		ERROR) errors=$((errors + 1)) ;;
		MEASURED) measurements=$((measurements + 1)) ;;
		esac
	done

	n=${#NOTES[@]}
	if ((n > 0)); then
		log ""
		log "notes (contract details, not security outcomes):"
		for ((i = 0; i < n; i++)); do
			log "  NOTE  ${NOTES[i]}"
		done
	fi

	log ""
	log "outcomes: $passes PASS, $failures FAIL, $errors ERROR, $measurements MEASURED"

	if ((failures > 0)); then
		log "verdict: $failures case(s) produced the WRONG security outcome"
		return 1
	fi
	if ((errors > 0)); then
		if [[ "$ALLOW_CASE_ERRORS" == "1" ]]; then
			log "verdict: $errors case(s) never reached a security decision. ALLOW_CASE_ERRORS=1 keeps the"
			log "         exit status at 0, so THIS RUN IS NOT COMPLETE EVIDENCE: the errored cases prove"
			log "         nothing and must not be recorded as passes."
			return 0
		fi
		log "verdict: $errors case(s) never reached a security decision — a dependency or precondition"
		log "         failed. Nothing was disproven and nothing was proven; fix the cause and rerun."
		return 1
	fi

	log "verdict: every selected lifecycle case behaved as designed"
	return 0
}

usage() {
	cat <<'EOF'
usage: lifecycle-matrix.sh

Drives the P8 nonce lifecycle cases against a live Incus host and broker. Select
cases with CASES (default "a b c d e f g h i"). See spike/p8/README.md for the
full environment-variable contract.

Every case ends in exactly one outcome: PASS (the security decision was observed
and correct), FAIL (it was wrong), ERROR (no decision was observed — a
dependency, precondition or backend failed) or, for case i only, MEASURED. An
ERROR is never a PASS and exits non-zero unless ALLOW_CASE_ERRORS=1.

Guest dependencies (GUEST_DEPS, default "curl jq openssl") are checked inside
every guest before it is used; GUEST_INSTALL_DEPS=1 installs the missing ones
with GUEST_INSTALL_CMD.

Exit: 0 all good, 1 a case FAILed or ERRORed, 2 preflight or usage, 3 cleanup was
incomplete (a nonce secret may still be live).
EOF
}

main() {
	case "${1:-}" in
	-h | --help)
		usage
		exit 0
		;;
	"") ;;
	*) die "unexpected argument: $1 (this script is configured by environment variables; try --help)" ;;
	esac

	local case_name
	for case_name in $CASES; do
		case "$case_name" in
		a | b | c | d | e | f | g | h | i) record "$case_name" PENDING "not run" ;;
		*) die "unknown case '$case_name' in CASES (valid: a b c d e f g h i)" ;;
		esac
	done

	section "preflight"
	preflight
	trap cleanup EXIT

	for case_name in $CASES; do
		case "$case_name" in
		a) case_a ;;
		b) case_b ;;
		c) case_c ;;
		d) case_d ;;
		e) case_e ;;
		f) case_f ;;
		g) case_g ;;
		h) case_h ;;
		i) case_i ;;
		esac
	done

	summary
}

main "$@"

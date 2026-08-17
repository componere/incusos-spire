#!/usr/bin/env bash
#
# lifecycle-matrix.sh — P8 lifecycle harness. Drives the nonce lifecycle cases of
# SPIKE_PLAN.md P8 steps 4 and 5 end to end against a live Incus host and a live
# incus-spiffe-broker, printing a verdict per case.
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
#   * Everything this script echoes from a guest is guest-bootstrap.sh output,
#     which is transcript-safe.
#   * The cleanup trap removes the guest staging directories that hold those
#     payload files, and clears user.spiffe-bootstrap on every instance it
#     touched, even when a case aborts (P8 rollback requirement).
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
#      outcome honestly as a go/no-go input and never lets it change the exit
#      status.
#
# Cases a-h fail the run when the security outcome is wrong: a rejection that was
# granted, or a grant that produced the wrong identity. A rejection carrying an
# unexpected status code is reported as a NOTE, because the reject/grant decision
# is the security property and the status code is a contract detail. Set
# STRICT_STATUS=1 to promote those notes to failures.
#
# Exit status: 0 when every selected case behaves, 1 when any case misbehaves,
# 2 for a preflight or environment failure.

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

# TTLs. MINT_TTL_SECONDS is sent with every mint except case c, which uses
# SHORT_TTL_SECONDS. If the broker ignores ttl_seconds, set EXPIRY_WAIT_SECONDS
# above its configured TTL so case c still measures a real expiry.
MINT_TTL_SECONDS="${MINT_TTL_SECONDS:-}"
SHORT_TTL_SECONDS="${SHORT_TTL_SECONDS:-5}"
EXPIRY_WAIT_SECONDS="${EXPIRY_WAIT_SECONDS:-}"

BOOTSTRAP_KEY="${BOOTSTRAP_KEY:-user.spiffe-bootstrap}"
GUEST_STAGE_DIR="${GUEST_STAGE_DIR:-/root/p8}"
GUEST_READY_TIMEOUT="${GUEST_READY_TIMEOUT:-180}"

CASES="${CASES:-a b c d e f g h i}"
STRICT_STATUS="${STRICT_STATUS:-0}"
# Leave the staging directories, the disposable instance and the snapshot in
# place for debugging. Those staging directories contain nonce payloads, so this
# is a deliberate, temporary choice.
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"

HARNESS_DIR="${HARNESS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
GUEST_SCRIPT="$HARNESS_DIR/guest-bootstrap.sh"
MINT_SCRIPT="$HARNESS_DIR/operator-mint.sh"

REMOTE_PREFIX=""
[[ -n "$INCUS_REMOTE" ]] && REMOTE_PREFIX="${INCUS_REMOTE%:}:"

GUEST_SCRIPT_IN_GUEST="$GUEST_STAGE_DIR/guest-bootstrap.sh"
GUEST_CACERT_IN_GUEST="$GUEST_STAGE_DIR/broker-ca.pem"

declare -a FAILURES=()
declare -a NOTES=()
declare -a MEASUREMENTS=()
declare -a GUEST_ENV=()
declare -a PREPARED_GUESTS=()
TMP_CREATED=0
SNAPSHOT_NAME=""
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

pass() {
	printf 'PASS  case %s: %s\n' "$1" "$2"
}

fail() {
	printf 'FAIL  case %s: %s\n' "$1" "$2"
	FAILURES+=("case $1: $2")
}

note() {
	printf 'NOTE  case %s: %s\n' "$1" "$2"
	NOTES+=("case $1: $2")
}

measured() {
	printf 'MEASURED  case %s: %s\n' "$1" "$2"
	MEASUREMENTS+=("case $1: $2")
}

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 2
}

# expect_status compares an observed rejection status with the documented one.
# A mismatch is a note by default, a failure under STRICT_STATUS=1.
expect_status() {
	local name="$1" want="$2" got="$3"
	[[ "$want" == "$got" ]] && return 0
	if [[ "$STRICT_STATUS" == "1" ]]; then
		fail "$name" "expected HTTP $want, observed HTTP $got (STRICT_STATUS=1)"
	else
		note "$name" "expected HTTP $want, observed HTTP $got — rejection stands, contract detail differs"
	fi
}

# --- Incus plumbing -----------------------------------------------------------

target() {
	printf '%s%s' "$REMOTE_PREFIX" "$1"
}

config_get() {
	"$INCUS_BIN" config get "$(target "$1")" "$2" --project "$PROJECT" 2>/dev/null | tr -d '\r\n'
}

clear_key() {
	"$INCUS_BIN" config unset "$(target "$1")" "$BOOTSTRAP_KEY" --project "$PROJECT" >/dev/null 2>&1 || true
}

instance_exists() {
	"$INCUS_BIN" info "$(target "$1")" --project "$PROJECT" >/dev/null 2>&1
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
# a 0700 staging directory inside the instance.
prepare_guest() {
	local guest="$1"
	"$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
		install -d -m 0700 "$GUEST_STAGE_DIR" >/dev/null
	"$INCUS_BIN" file push "$GUEST_SCRIPT" "$(target "$guest")$GUEST_SCRIPT_IN_GUEST" \
		--project "$PROJECT" --mode 0700 >/dev/null
	if [[ -n "$BROKER_CACERT" ]]; then
		"$INCUS_BIN" file push "$BROKER_CACERT" "$(target "$guest")$GUEST_CACERT_IN_GUEST" \
			--project "$PROJECT" --mode 0600 >/dev/null
	fi
	local seen
	for seen in ${PREPARED_GUESTS[@]+"${PREPARED_GUESTS[@]}"}; do
		[[ "$seen" == "$guest" ]] && return 0
	done
	PREPARED_GUESTS+=("$guest")
}

# copy_payload moves a bootstrap payload from one instance to another through a
# pipe. The secret never touches the operator's disk and never enters a variable.
copy_payload() {
	local src="$1" src_path="$2" dst="$3" dst_path="$4"
	"$INCUS_BIN" file pull "$(target "$src")$src_path" - --project "$PROJECT" |
		"$INCUS_BIN" file push - "$(target "$dst")$dst_path" --project "$PROJECT" --mode 0600 >/dev/null
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

# mint asks the broker for a nonce. $1 is the instance UUID, $2 an optional TTL
# override in seconds. Sets MINT_RC and the MINT_* fields.
mint() {
	local uuid="$1" ttl="${2:-$MINT_TTL_SECONDS}"
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

# mint_or_fail mints and fails the case when the mint did not succeed. Returns
# non-zero so the caller can abandon the case.
mint_or_fail() {
	local name="$1" uuid="$2" ttl="${3:-$MINT_TTL_SECONDS}"
	mint "$uuid" "$ttl"
	if ((MINT_RC != 0)) || [[ -z "$MINT_NONCE_ID" ]]; then
		fail "$name" "mint failed for instance_uuid=$uuid (operator-mint.sh exit $MINT_RC); see the [mint] transcript above"
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
	clear_key "$GUEST_A"
	mint_or_fail "$name" "$GUEST_A_UUID" || return 0

	step "guest A reads its own bootstrap key"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/a-payload.json"
	if ((GUEST_RC != 0)); then
		fail "$name" "guest A could not read $BOOTSTRAP_KEY through /dev/incus/sock (exit $GUEST_RC)"
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
	local status uuid name_resolved selectors
	status=$(result_field "$GUEST_OUT" status)
	uuid=$(result_field "$GUEST_OUT" instance_uuid)
	name_resolved=$(result_field "$GUEST_OUT" instance_name)
	selectors=$(result_field "$GUEST_OUT" selectors)
	if ((GUEST_RC != 0)); then
		fail "$name" "redemption of a fresh nonce was refused with HTTP ${status:-none} (exit $GUEST_RC)"
		return 0
	fi
	if [[ -n "$uuid" && "$uuid" != "-" && "$uuid" != "$GUEST_A_UUID" ]]; then
		fail "$name" "granted, but the broker resolved instance_uuid=$uuid instead of A's $GUEST_A_UUID"
		return 0
	fi
	if [[ -n "$name_resolved" && "$name_resolved" != "-" && "$name_resolved" != "$GUEST_A" ]]; then
		fail "$name" "granted, but the broker resolved instance_name=$name_resolved instead of $GUEST_A; P6 makes names reusable, so the write target must re-resolve to A"
		return 0
	fi
	pass "$name" "guest A redeemed its own nonce ($MINT_NONCE_ID) through /dev/incus/sock, HTTP $status, selectors=${selectors:--}"
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
	clear_key "$GUEST_A"
	mint_or_fail "$name" "$GUEST_A_UUID" || return 0

	step "stage the payload inside guest A, then redeem once"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/b-payload.json"
	if ((GUEST_RC != 0)); then
		fail "$name" "setup: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	run_guest "$GUEST_A" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/b-payload.json"
	if ((GUEST_RC != 0)); then
		fail "$name" "setup: the first redemption failed, so reuse cannot be measured (exit $GUEST_RC)"
		return 0
	fi

	step "redeem the very same nonce a second time"
	run_guest "$GUEST_A" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/b-payload.json"
	local status
	status=$(result_field "$GUEST_OUT" status)
	if ((GUEST_RC == 0)); then
		fail "$name" "the same nonce was redeemed TWICE (HTTP $status): single use is not enforced"
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
	clear_key "$GUEST_A"
	mint_or_fail "$name" "$GUEST_A_UUID" "$SHORT_TTL_SECONDS" || return 0

	local wait_for="${EXPIRY_WAIT_SECONDS:-$((SHORT_TTL_SECONDS + 3))}"
	step "waiting ${wait_for}s for the nonce to expire (requested TTL ${SHORT_TTL_SECONDS}s, expires_at=${MINT_EXPIRES_AT:--})"
	log "    if the broker ignores ttl_seconds, set EXPIRY_WAIT_SECONDS above its configured TTL"
	sleep "$wait_for"

	step "redeem after expiry"
	run_guest "$GUEST_A" MODE=redeem
	local status
	status=$(result_field "$GUEST_OUT" status)
	if ((GUEST_RC == 0)); then
		fail "$name" "an expired nonce was still redeemed (HTTP $status): expiry is not enforced"
		return 0
	fi
	if [[ -z "$status" || "$status" == "000" ]]; then
		fail "$name" "no HTTP status was obtained, so expiry was not measured (exit $GUEST_RC)"
		return 0
	fi
	pass "$name" "the expired nonce $MINT_NONCE_ID was rejected with HTTP $status"
	expect_status "$name" 409 "$status"
}

# case_d proves the atomic consume: two simultaneous redemptions of one nonce,
# exactly one success. Both run inside guest A against one staged payload.
case_d() {
	local name="d"
	section "case $name — two CONCURRENT redemptions yield exactly one success (P8 step 4)"
	clear_key "$GUEST_A"
	mint_or_fail "$name" "$GUEST_A_UUID" || return 0

	step "stage the payload inside guest A"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/d-payload.json"
	if ((GUEST_RC != 0)); then
		fail "$name" "setup: guest A could not read its bootstrap key (exit $GUEST_RC)"
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
	local status1 status2
	status1=$(result_field "$(cat "$out1")" status)
	status2=$(result_field "$(cat "$out2")" status)
	rm -f -- "$out1" "$out2"

	local successes=0
	# Plain if blocks, not `&& ((n++))`: an arithmetic command whose result is
	# zero returns status 1, and under set -e that would abort the case.
	if ((rc1 == 0)); then successes=$((successes + 1)); fi
	if ((rc2 == 0)); then successes=$((successes + 1)); fi
	log "    attempt 1: exit $rc1 HTTP ${status1:-none}"
	log "    attempt 2: exit $rc2 HTTP ${status2:-none}"

	case "$successes" in
	1)
		pass "$name" "exactly one of two concurrent redemptions of $MINT_NONCE_ID succeeded (HTTP $status1 / $status2)"
		local loser="$status1"
		((rc1 == 0)) && loser="$status2"
		expect_status "$name" 409 "$loser"
		;;
	0)
		fail "$name" "both concurrent redemptions failed (HTTP $status1 / $status2): the nonce was consumed by neither"
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

	if instance_exists "$TMP_INSTANCE"; then
		step "removing a leftover $TMP_INSTANCE first"
		"$INCUS_BIN" delete "$(target "$TMP_INSTANCE")" --project "$PROJECT" --force >/dev/null
	fi

	step "creating the disposable instance $TMP_INSTANCE ($TMP_TYPE, $TMP_IMAGE)"
	local -a launch=(launch "$TMP_IMAGE" "$(target "$TMP_INSTANCE")" --project "$PROJECT")
	[[ "$TMP_TYPE" == "vm" ]] && launch+=(--vm)
	if ! "$INCUS_BIN" "${launch[@]}" >/dev/null; then
		fail "$name" "could not launch $TMP_INSTANCE from $TMP_IMAGE"
		return 0
	fi
	TMP_CREATED=1

	if ! wait_for_guest "$TMP_INSTANCE"; then
		fail "$name" "$TMP_INSTANCE never exposed /dev/incus/sock within ${GUEST_READY_TIMEOUT}s"
		return 0
	fi
	prepare_guest "$TMP_INSTANCE"

	local tmp_uuid
	tmp_uuid=$(config_get "$TMP_INSTANCE" volatile.uuid)
	if [[ -z "$tmp_uuid" ]]; then
		fail "$name" "could not read volatile.uuid of $TMP_INSTANCE"
		return 0
	fi
	log "    $TMP_INSTANCE volatile.uuid=$tmp_uuid"

	mint_or_fail "$name" "$tmp_uuid" || return 0

	step "stage the payload inside the disposable instance, then pipe it into guest B"
	run_guest "$TMP_INSTANCE" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/e-payload.json"
	if ((GUEST_RC != 0)); then
		fail "$name" "setup: $TMP_INSTANCE could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	copy_payload "$TMP_INSTANCE" "$GUEST_STAGE_DIR/e-payload.json" "$GUEST_B" "$GUEST_STAGE_DIR/e-payload.json"

	step "deleting $TMP_INSTANCE, then redeeming its still-unused nonce from guest B"
	"$INCUS_BIN" delete "$(target "$TMP_INSTANCE")" --project "$PROJECT" --force >/dev/null
	TMP_CREATED=0

	run_guest "$GUEST_B" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/e-payload.json"
	local status
	status=$(result_field "$GUEST_OUT" status)
	if ((GUEST_RC == 0)); then
		fail "$name" "a nonce bound to a DELETED instance was redeemed (HTTP $status)"
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
	clear_key "$GUEST_A"
	mint_or_fail "$name" "$GUEST_A_UUID" || return 0

	local gen_before
	gen_before=$(config_get "$GUEST_A" volatile.uuid.generation)
	log "    generation before: ${gen_before:-<absent>}"

	step "stage the payload, then stash it in guest B so it survives the restore"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/f-payload.json"
	if ((GUEST_RC != 0)); then
		fail "$name" "setup: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	copy_payload "$GUEST_A" "$GUEST_STAGE_DIR/f-payload.json" "$GUEST_B" "$GUEST_STAGE_DIR/f-payload.json"

	SNAPSHOT_NAME="p8-generation-$$"
	step "snapshot and restore guest A as $SNAPSHOT_NAME"
	"$INCUS_BIN" snapshot create "$(target "$GUEST_A")" "$SNAPSHOT_NAME" --project "$PROJECT" >/dev/null
	"$INCUS_BIN" stop "$(target "$GUEST_A")" --project "$PROJECT" >/dev/null
	"$INCUS_BIN" snapshot restore "$(target "$GUEST_A")" "$SNAPSHOT_NAME" --project "$PROJECT" >/dev/null
	"$INCUS_BIN" start "$(target "$GUEST_A")" --project "$PROJECT" >/dev/null
	if ! wait_for_guest "$GUEST_A"; then
		fail "$name" "guest A did not come back after the restore within ${GUEST_READY_TIMEOUT}s"
		return 0
	fi
	# The restore reverted the filesystem, so the staging directory is gone.
	prepare_guest "$GUEST_A"

	local gen_after
	gen_after=$(config_get "$GUEST_A" volatile.uuid.generation)
	log "    generation after:  ${gen_after:-<absent>}"
	if [[ -z "$gen_after" || "$gen_after" == "$gen_before" ]]; then
		fail "$name" "the restore did not install a fresh generation (before=$gen_before after=$gen_after), contradicting P6; the case cannot measure invalidation"
		return 0
	fi

	step "pipe the pre-restore payload back into guest A and redeem it"
	copy_payload "$GUEST_B" "$GUEST_STAGE_DIR/f-payload.json" "$GUEST_A" "$GUEST_STAGE_DIR/f-payload.json"
	run_guest "$GUEST_A" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/f-payload.json"
	local status
	status=$(result_field "$GUEST_OUT" status)
	if ((GUEST_RC == 0)); then
		fail "$name" "a nonce minted against generation $gen_before was redeemed after the generation became $gen_after (HTTP $status)"
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
	clear_key "$GUEST_A"
	clear_key "$GUEST_B"
	mint_or_fail "$name" "$GUEST_A_UUID" || return 0

	step "guest A reads its key, for the digest to compare against"
	run_guest "$GUEST_A" MODE=fetch
	if ((GUEST_RC != 0)); then
		fail "$name" "setup: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	local a_digest
	a_digest=$(result_field "$GUEST_OUT" payload_sha256)
	log "    A payload sha256=$a_digest (digests are permitted in evidence; values are not)"

	step "guest B attempts the same read through its own /dev/incus/sock"
	run_guest "$GUEST_B" MODE=fetch
	local socket_status b_digest
	socket_status=$(result_field "$GUEST_OUT" socket_status)
	b_digest=$(result_field "$GUEST_OUT" payload_sha256)

	if ((GUEST_RC != 0)); then
		if [[ "$socket_status" == "404" || "$socket_status" == "403" ]]; then
			pass "$name" "guest B's socket exposes no $BOOTSTRAP_KEY (HTTP $socket_status); A's nonce is unreachable from B"
		else
			pass "$name" "guest B obtained no bootstrap value (exit $GUEST_RC, socket HTTP ${socket_status:-none})"
			expect_status "$name" 404 "${socket_status:-none}"
		fi
		return 0
	fi

	if [[ -n "$b_digest" && "$b_digest" == "$a_digest" ]]; then
		fail "$name" "guest B read A's exact bootstrap payload (matching sha256=$b_digest): the delivery channel is not per-instance"
	else
		fail "$name" "guest B read a bootstrap value of its own (sha256=$b_digest) although no nonce was minted for it"
	fi
}

# case_h proves the claimed UUID is untrusted input: B presents B's own nonce and
# asks for A's identity. The broker must resolve only B.
case_h() {
	local name="h"
	section "case $name — guest B claims A's UUID with B's own nonce (P8 step 5)"
	clear_key "$GUEST_A"
	clear_key "$GUEST_B"
	mint_or_fail "$name" "$GUEST_B_UUID" || return 0

	step "guest B redeems its own nonce while claiming instance_uuid=$GUEST_A_UUID"
	run_guest "$GUEST_B" MODE=redeem CLAIM_UUID="$GUEST_A_UUID"
	local status uuid name_resolved spiffe_id selectors
	status=$(result_field "$GUEST_OUT" status)
	uuid=$(result_field "$GUEST_OUT" instance_uuid)
	name_resolved=$(result_field "$GUEST_OUT" instance_name)
	spiffe_id=$(result_field "$GUEST_OUT" spiffe_id)
	selectors=$(result_field "$GUEST_OUT" selectors)

	if ((GUEST_RC != 0)); then
		pass "$name" "the claim was refused outright (HTTP $status); B obtained no identity at all"
		note "$name" "SPIKE_PLAN.md expects the claim to be ignored rather than rejected, so B should normally"
		note "$name" "still receive B's own identity here. A rejection is safe but is a contract difference."
		return 0
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
	if [[ -n "$uuid" && "$uuid" != "-" && "$uuid" != "$GUEST_B_UUID" ]]; then
		fail "$name" "B received an identity for neither A nor B (instance_uuid=$uuid)"
		return 0
	fi
	pass "$name" "the claimed UUID was ignored; the broker resolved only B (instance_uuid=${uuid:--}, instance_name=${name_resolved:--}, selectors=${selectors:--})"
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
# what happens and never changes the exit status.
case_i() {
	local name="i"
	section "case $name — MEASURING A KNOWN LIMITATION: leaked unused A nonce used from B (P8 step 5)"
	log "This case is expected to SUCCEED. An unused nonce is a bearer credential; a success here is"
	log "the recorded bearer-token risk and a go/no-go input, not a bug and not a run failure."
	clear_key "$GUEST_A"
	mint "$GUEST_A_UUID" "$MINT_TTL_SECONDS"
	if ((MINT_RC != 0)) || [[ -z "$MINT_NONCE_ID" ]]; then
		measured "$name" "NOT MEASURED: the mint for A failed (operator-mint.sh exit $MINT_RC)"
		return 0
	fi

	step "stage A's payload, then pipe it into guest B — the deliberate leak"
	run_guest "$GUEST_A" MODE=fetch PAYLOAD_OUT="$GUEST_STAGE_DIR/i-payload.json"
	if ((GUEST_RC != 0)); then
		measured "$name" "NOT MEASURED: guest A could not read its bootstrap key (exit $GUEST_RC)"
		return 0
	fi
	copy_payload "$GUEST_A" "$GUEST_STAGE_DIR/i-payload.json" "$GUEST_B" "$GUEST_STAGE_DIR/i-payload.json"

	step "guest B redeems A's unused nonce"
	run_guest "$GUEST_B" MODE=redeem PAYLOAD_FILE="$GUEST_STAGE_DIR/i-payload.json"
	local status uuid name_resolved spiffe_id selectors
	status=$(result_field "$GUEST_OUT" status)
	uuid=$(result_field "$GUEST_OUT" instance_uuid)
	name_resolved=$(result_field "$GUEST_OUT" instance_name)
	spiffe_id=$(result_field "$GUEST_OUT" spiffe_id)
	selectors=$(result_field "$GUEST_OUT" selectors)

	if ((GUEST_RC != 0)); then
		measured "$name" "the leaked unused nonce was REJECTED from B (HTTP $status). The prototype binds the caller by something beyond possession; record what, because SPIKE_PLAN.md expected a success."
		return 0
	fi
	if [[ "$uuid" == "$GUEST_A_UUID" || "$name_resolved" == "$GUEST_A" || "$spiffe_id" == *"$GUEST_A"* ]]; then
		measured "$name" "CONFIRMED bearer-token risk: B redeemed A's leaked nonce and received A's identity (instance_uuid=${uuid:--}, instance_name=${name_resolved:--}, selectors=${selectors:--}, HTTP $status). Expected per SPIKE_PLAN.md P8 step 5; go/no-go input."
		return 0
	fi
	measured "$name" "the leaked nonce was accepted from B but resolved to instance_uuid=${uuid:--} / instance_name=${name_resolved:--} rather than A (HTTP $status): possession alone did not transfer A's identity."
}

# --- Preflight and cleanup ----------------------------------------------------

cleanup() {
	local rc=$?
	printf '\n=== cleanup (runs on abort too: P8 requires config keys cleared either way)\n'

	local guest
	for guest in "$GUEST_A" "$GUEST_B"; do
		clear_key "$guest"
		log "cleared $BOOTSTRAP_KEY on $guest"
	done

	if [[ -n "$SNAPSHOT_NAME" ]] && [[ "$KEEP_ARTIFACTS" != "1" ]]; then
		"$INCUS_BIN" snapshot delete "$(target "$GUEST_A")" "$SNAPSHOT_NAME" --project "$PROJECT" >/dev/null 2>&1 &&
			log "deleted snapshot $SNAPSHOT_NAME" || log "could not delete snapshot $SNAPSHOT_NAME (check by hand)"
	fi

	if ((TMP_CREATED)) && [[ "$KEEP_ARTIFACTS" != "1" ]]; then
		clear_key "$TMP_INSTANCE"
		"$INCUS_BIN" delete "$(target "$TMP_INSTANCE")" --project "$PROJECT" --force >/dev/null 2>&1 &&
			log "deleted $TMP_INSTANCE" || log "could not delete $TMP_INSTANCE (check by hand)"
	fi

	if [[ "$KEEP_ARTIFACTS" == "1" ]]; then
		log "KEEP_ARTIFACTS=1: staging directories left in place. They contain nonce payloads:"
		log "  remove $GUEST_STAGE_DIR inside each guest before capturing evidence."
	else
		for guest in ${PREPARED_GUESTS[@]+"${PREPARED_GUESTS[@]}"}; do
			if "$INCUS_BIN" exec "$(target "$guest")" --project "$PROJECT" -- \
				rm -rf "$GUEST_STAGE_DIR" >/dev/null 2>&1; then
				log "removed $GUEST_STAGE_DIR in $guest (it held nonce payloads)"
			else
				log "could not remove $GUEST_STAGE_DIR in $guest — it holds nonce payloads, clear it by hand"
			fi
		done
	fi

	exit "$rc"
}

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

	local guest
	for guest in "$GUEST_A" "$GUEST_B"; do
		instance_exists "$guest" || die "instance $guest does not exist in project $PROJECT on remote '${INCUS_REMOTE:-local}'"
		wait_for_guest "$guest" || die "$guest does not expose /dev/incus/sock (container: security.guestapi; VM: incus-agent must be running)"
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

	prepare_guest "$GUEST_A"
	prepare_guest "$GUEST_B"

	log "remote:            ${INCUS_REMOTE:-<local daemon>}"
	log "project:           $PROJECT"
	log "guest A:           $GUEST_A (volatile.uuid=$GUEST_A_UUID)"
	log "guest B:           $GUEST_B (volatile.uuid=$GUEST_B_UUID)"
	log "broker:            $BROKER_URL (mint $NONCE_PATH, redeem $REDEEM_PATH)"
	log "bootstrap key:     $BOOTSTRAP_KEY"
	log "guest staging dir: $GUEST_STAGE_DIR"
	log "cases:             $CASES"
	log "strict status:     $STRICT_STATUS"
}

usage() {
	cat <<'EOF'
usage: lifecycle-matrix.sh

Drives the P8 nonce lifecycle cases against a live Incus host and broker. Select
cases with CASES (default "a b c d e f g h i"). See spike/p8/README.md for the
full environment-variable contract. Case i is a measurement of a known bearer
token limitation and never changes the exit status.
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

	section "preflight"
	preflight
	trap cleanup EXIT

	local case_name
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
		*) die "unknown case '$case_name' in CASES (valid: a b c d e f g h i)" ;;
		esac
	done

	section "summary"
	local entry
	if ((${#MEASUREMENTS[@]} > 0)); then
		log "measurements (never affect the exit status):"
		for entry in "${MEASUREMENTS[@]}"; do
			log "  MEASURED  $entry"
		done
	fi
	if ((${#NOTES[@]} > 0)); then
		log "notes:"
		for entry in "${NOTES[@]}"; do
			log "  NOTE  $entry"
		done
	fi
	if ((${#FAILURES[@]} > 0)); then
		log "failures:"
		for entry in "${FAILURES[@]}"; do
			log "  FAIL  $entry"
		done
		log ""
		log "verdict: ${#FAILURES[@]} case(s) misbehaved"
		return 1
	fi

	log ""
	log "verdict: every selected lifecycle case behaved as designed"
	return 0
}

main "$@"

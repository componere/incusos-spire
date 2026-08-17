#!/usr/bin/env bash
#
# guest-bootstrap.sh — P8 guest-side bootstrap harness. Runs as root INSIDE a
# spike guest (container or VM), reads the instance's one-time nonce from its own
# /dev/incus/sock, and redeems it with the incus-spiffe-broker.
#
# THROWAWAY spike tooling. Appendix C of SPIKE_PLAN.md classifies everything
# under spike/ as never merged as product code: it is deletable without loss,
# because the evidence it produces lives in the journal. Do not import, wrap, or
# promote any of this. The durable counterparts are cmd/incus-spiffe-broker,
# internal/nonce, and internal/incus/bootstrap.
#
# ---------------------------------------------------------------------------
# SECRET HANDLING — Appendix D rules 1 and 5
# ---------------------------------------------------------------------------
# The bootstrap value carries the nonce secret. The P8 live run captures this
# script's stdout and stderr verbatim as evidence, so the script must never emit
# that secret:
#
#   * It prints nonce IDs, payload SHA-256 digests, certificate fingerprints and
#     HTTP status codes only. Never the value.
#   * The secret is never echoed and never placed on a command line: argv is
#     world-readable through /proc, so the request body is piped to curl on
#     stdin (--data-binary @-), it is built inside jq from jq's own stdin, and
#     grep patterns are read from stdin too (grep -f -).
#   * Response bodies are never printed raw: a broken broker could echo the nonce
#     back. Only named, non-secret fields are printed — binding metadata and the
#     frozen incus: selectors, which Appendix D rule 3 permits — and only after a
#     guard that withholds any body containing the secret.
#   * PAYLOAD_OUT writes under umask 077, so anything the script persists is mode
#     0600 and root-only.
#
# ---------------------------------------------------------------------------
# GUEST READ SHAPE — source-pinned to Incus v7.3.0 (evidence/p8/GUEST_SOCK_BRIEF.md)
# ---------------------------------------------------------------------------
#   GET /1.0/config/user.spiffe-bootstrap over /dev/incus/sock
#
# returns the exact configured string with Content-Type: application/octet-stream
# — no Incus JSON envelope, no server-added newline. Only user.* and cloud-init.*
# keys are visible: a guest cannot read volatile.uuid or volatile.uuid.generation
# and so cannot prove its own instance identity. The broker must resolve the
# UUID/generation binding server-side; possession of this value is a bearer
# credential. A missing key is HTTP 404; a forbidden key or security.guestapi=false
# is HTTP 403. Guest UID 0 is required (containers enforce a peer-UID check, VMs
# rely on socket mode 0600). A VM additionally needs incus-agent running. The
# guest cannot write or clear the key, so single use is enforced entirely
# server-side.
#
# ---------------------------------------------------------------------------
# MODES
# ---------------------------------------------------------------------------
#   MODE=redeem (default)  obtain the payload, then POST nonce_id + nonce to the
#                          broker's redeem endpoint over pinned TLS.
#   MODE=fetch             obtain the payload and report its nonce ID, broker
#                          URL, fingerprint and digest. With PAYLOAD_OUT set,
#                          persist the raw payload (mode 0600) so the operator
#                          harness can stage it for the wrong-instance,
#                          deleted-instance, generation-change and concurrency
#                          cases without any secret crossing a transcript.
#
# ---------------------------------------------------------------------------
# EXIT CODES (lifecycle-matrix.sh judges on these plus the final RESULT line)
# ---------------------------------------------------------------------------
#   0   success: redemption granted, or fetch completed
#   2   usage or missing dependency
#   3   guest socket read failed (key absent, forbidden, or socket missing)
#   4   payload present but malformed or missing a required field
#   5   TLS pin failure: the broker certificate does not match the fingerprint
#       carried in the payload. The secret is NOT sent in this case.
#   10  broker answered 401 (unauthorized: unknown, mismatched, expired,
#       wrong-instance, or generation-invalidated nonce)
#   11  broker answered 409 (conflict: the nonce was already consumed)
#   12  broker answered 500 (broker internal error)
#   13  broker answered 503 (broker dependency unavailable)
#   14  broker answered some other non-2xx status
#   15  transport failure: no HTTP status was obtained

set -euo pipefail
umask 077

# --- Parameters ---------------------------------------------------------------

# Binaries. openssl is mandatory in redeem mode: it is how the broker
# certificate is pinned to the fingerprint carried in the payload.
CURL_BIN="${CURL_BIN:-curl}"
JQ_BIN="${JQ_BIN:-jq}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

# Guest API. Identical for containers and VMs per GUEST_SOCK_BRIEF.md.
GUEST_SOCKET="${GUEST_SOCKET:-/dev/incus/sock}"
BOOTSTRAP_KEY="${BOOTSTRAP_KEY:-user.spiffe-bootstrap}"

MODE="${MODE:-redeem}"

# Payload staging. PAYLOAD_FILE replaces the socket read, which is how the
# operator harness exercises a nonce from a guest that is not its owner, or a
# nonce whose instance has been deleted. PAYLOAD_OUT persists what was read.
PAYLOAD_FILE="${PAYLOAD_FILE:-}"
PAYLOAD_OUT="${PAYLOAD_OUT:-}"

# An untrusted instance_uuid claim added to the redeem body. The broker must
# ignore it and resolve only the caller's own binding (SPIKE_PLAN.md P8 step 5).
CLAIM_UUID="${CLAIM_UUID:-}"

# Broker endpoint. The payload's broker_url is authoritative; the override
# exists for split-horizon DNS on the spike bridge.
BROKER_URL_OVERRIDE="${BROKER_URL_OVERRIDE:-}"
REDEEM_PATH="${REDEEM_PATH:-/v1alpha1/redeem}"

# TLS. BROKER_CACERT is the spike CA that issued the broker server certificate;
# with it, curl performs an ordinary chain validation on top of the fingerprint
# pin. Without it the fetched self-signed leaf is used as its own trust anchor,
# which only works when the broker certificate is self-signed.
BROKER_CACERT="${BROKER_CACERT:-}"
BROKER_TLS_HOSTNAME="${BROKER_TLS_HOSTNAME:-}"
ALLOW_INSECURE_TLS="${ALLOW_INSECURE_TLS:-0}"

CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-20}"

readonly SOCKET_URL_BASE='http://localhost/1.0/config'

WORK_DIR=""

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

cleanup() {
	if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
		rm -rf -- "$WORK_DIR" || true
	fi
	return 0
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 || die 2 "$2 not found: $1 (override with $3)"
}

# is_ip_literal reports whether the argument is an address rather than a name.
# SNI must be omitted for an address literal.
is_ip_literal() {
	[[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ || "$1" == *:* ]]
}

# normalize_fingerprint lowercases a certificate fingerprint and strips the
# separators and the algorithm prefix that different tools add, so a payload
# value and an openssl value can be compared as plain hex.
normalize_fingerprint() {
	printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d ': \t\n' | sed -e 's/^sha256//'
}

# sha256_stdin digests stdin. Used for payload digests, which Appendix D rule 5
# explicitly permits in evidence.
sha256_stdin() {
	"$OPENSSL_BIN" dgst -sha256 | awk '{print $NF}'
}

# body_leaks_secret reports whether a response body contains the nonce value. The
# pattern comes from SECRET_FILE, a 0600 file in the work directory, so the secret
# never reaches grep's argv and never occupies a shell variable.
body_leaks_secret() {
	local file="$1"
	[[ -n "$SECRET_FILE" && -s "$SECRET_FILE" ]] || return 1
	grep -q -F -f "$SECRET_FILE" -- "$file"
}

# json_field prints the first non-empty value among the supplied field names.
# The harness pins one canonical spelling per field and accepts the obvious
# alternate, because a spike broker's field naming is not a frozen contract.
json_field() {
	local file="$1"
	shift
	local names=("$@") filter=""
	local name
	for name in "${names[@]}"; do
		filter+="${filter:+, }.\"${name}\"?"
	done
	"$JQ_BIN" -r "first((${filter}) | select(. != null and . != \"\")) // \"\"" <"$file" 2>/dev/null || printf ''
}

# --- Payload acquisition ------------------------------------------------------

# read_payload_to_file performs the guest read described in GUEST_SOCK_BRIEF.md
# and leaves the raw configured string in the file named by $1. Those bytes are
# the secret-bearing payload; they are only ever consumed by jq, and no code path
# prints them.
read_payload_to_file() {
	local out="$1" status
	set +e
	status=$("$CURL_BIN" --silent --show-error \
		--unix-socket "$GUEST_SOCKET" \
		--output "$out" \
		--write-out '%{http_code}' \
		"$SOCKET_URL_BASE/$BOOTSTRAP_KEY" 2>"$WORK_DIR/socket.err")
	local rc=$?
	set -e

	if ((rc != 0)) || [[ -z "$status" ]]; then
		log "socket_read: transport failure against $GUEST_SOCKET"
		sed -e 's/^/socket_read: /' "$WORK_DIR/socket.err" >&2 || true
		log "RESULT mode=$MODE outcome=error socket_status=000 nonce_id=-"
		die 3 "cannot reach $GUEST_SOCKET (container: security.guestapi must not be false; VM: incus-agent must be running; must run as guest root)"
	fi

	log "socket_read: GET /1.0/config/$BOOTSTRAP_KEY -> HTTP $status"

	case "$status" in
	200) ;;
	404)
		log "RESULT mode=$MODE outcome=error socket_status=404 nonce_id=-"
		die 3 "$BOOTSTRAP_KEY is not set on this instance (HTTP 404): no nonce has been minted for it"
		;;
	403)
		log "RESULT mode=$MODE outcome=error socket_status=403 nonce_id=-"
		die 3 "guest API refused the key (HTTP 403): security.guestapi is false, or the key is outside user.*/cloud-init.*"
		;;
	401)
		log "RESULT mode=$MODE outcome=error socket_status=401 nonce_id=-"
		die 3 "guest API refused the caller (HTTP 401): the bootstrap value is readable by guest root only"
		;;
	*)
		log "RESULT mode=$MODE outcome=error socket_status=$status nonce_id=-"
		die 3 "unexpected guest API status $status"
		;;
	esac

	# The response has no JSON envelope and no trailing newline. It stays in the
	# file: nothing prints it.
}

# --- TLS pinning --------------------------------------------------------------

# pin_broker_certificate fetches the broker's leaf certificate, verifies it
# against the fingerprint carried in the bootstrap payload, and fills
# PINNED_LEAF/PINNED_SPKI so the redeem call can pin the very certificate that
# was verified. A mismatch aborts before the secret is sent anywhere.
#
# curl has no "pin this certificate fingerprint" flag: --pinnedpubkey pins the
# SHA-256 of the SubjectPublicKeyInfo, not of the certificate. So the fingerprint
# comparison is done here with openssl, and the SPKI hash of the same fetched
# certificate is then handed to curl. An impostor would have to present a
# certificate whose DER digest equals the payload fingerprint.
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
		sed -e 's/^/tls: /' "$WORK_DIR/s_client.err" >&2 || true
		log "RESULT mode=$MODE outcome=error status=000 nonce_id=$NONCE_ID reason=tls_handshake_failed"
		die 15 "cannot fetch the broker certificate from $host:$port"
	fi

	[[ -s "$PINNED_LEAF" ]] || {
		sed -e 's/^/tls: /' "$WORK_DIR/s_client.err" >&2 || true
		log "RESULT mode=$MODE outcome=error status=000 nonce_id=$NONCE_ID reason=no_certificate"
		die 15 "the broker at $host:$port presented no certificate"
	}

	local observed
	observed=$(normalize_fingerprint "$("$OPENSSL_BIN" x509 -in "$PINNED_LEAF" -noout -fingerprint -sha256 | cut -d= -f2)")
	local want
	want=$(normalize_fingerprint "$expected")

	log "tls: broker_fingerprint expected=$want observed=$observed"

	if [[ "$observed" != "$want" ]]; then
		log "RESULT mode=$MODE outcome=error status=000 nonce_id=$NONCE_ID reason=fingerprint_mismatch"
		die 5 "broker certificate fingerprint does not match the pinned value in the bootstrap payload; the nonce was NOT sent"
	fi

	PINNED_SPKI=$("$OPENSSL_BIN" x509 -in "$PINNED_LEAF" -pubkey -noout |
		"$OPENSSL_BIN" pkey -pubin -outform der |
		"$OPENSSL_BIN" dgst -sha256 -binary |
		"$OPENSSL_BIN" enc -base64)
	log "tls: pinned SPKI sha256//$PINNED_SPKI"
}

# --- Redemption ---------------------------------------------------------------

# diagnose_status prints the distinct diagnosis the live run needs for a broker
# status and sets STATUS_EXIT to this script's exit code for it. It sets a global
# rather than echoing the code, because everything it prints goes to stdout as
# evidence.
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
		log "         generation moved (a snapshot restore). Single use is enforced server-side by one"
		log "         compare-and-set; the guest cannot clear the key."
		STATUS_EXIT=11
		;;
	400)
		log "verdict: REJECTED 400 invalid request — the broker could not parse the body or the"
		log "         reference it built from the binding. A harness bug, not a lifecycle result."
		STATUS_EXIT=14
		;;
	500)
		log "verdict: ERROR 500 — broker internal failure. Not a security verdict: capture the"
		log "         broker log for this nonce ID before rerunning."
		STATUS_EXIT=12
		;;
	503)
		log "verdict: ERROR 503 — a broker dependency is unavailable (nonce store, or the Incus"
		log "         API through the read-only attestor credential). Retryable, not a rejection."
		STATUS_EXIT=13
		;;
	*)
		log "verdict: UNEXPECTED $1 — not one of 200/401/409/500/503."
		STATUS_EXIT=14
		;;
	esac
}

# redeem posts the nonce ID and secret to the broker. The body is built by jq
# from the payload on jq's stdin and handed to curl on curl's stdin, so the
# secret never appears in argv, in a log line, or in a temporary file.
redeem() {
	local payload_file="$1" host="$2" port="$3"

	local request_host="$host"
	local -a connect_to=()
	if [[ -n "$BROKER_TLS_HOSTNAME" && "$BROKER_TLS_HOSTNAME" != "$host" ]]; then
		request_host="$BROKER_TLS_HOSTNAME"
		connect_to=(--connect-to "$BROKER_TLS_HOSTNAME:$port:$host:$port")
	fi

	local url="https://$request_host:$port$REDEEM_PATH"
	log "redeem: POST $url nonce_id=$NONCE_ID claimed_instance_uuid=${CLAIM_UUID:--}"

	local -a tls=(--pinnedpubkey "sha256//$PINNED_SPKI")
	if [[ -n "$BROKER_CACERT" ]]; then
		[[ -r "$BROKER_CACERT" ]] || die 2 "BROKER_CACERT is not readable: $BROKER_CACERT"
		tls+=(--cacert "$BROKER_CACERT")
		log "redeem: chain validation against BROKER_CACERT=$BROKER_CACERT plus the SPKI pin"
	elif [[ "$ALLOW_INSECURE_TLS" == "1" ]]; then
		# Explicit opt-in only, and still not blind: the fingerprint of the
		# presented certificate was already compared against the payload value,
		# and --pinnedpubkey re-pins that same key for this request.
		tls+=(--insecure)
		warn "ALLOW_INSECURE_TLS=1: curl chain and hostname validation are DISABLED for this request."
		warn "The broker is still pinned by certificate fingerprint and by SPKI hash, but record this"
		warn "in the evidence: the run did not prove chain validation. Prefer BROKER_CACERT."
	else
		tls+=(--cacert "$PINNED_LEAF")
		log "redeem: using the pinned leaf as its own trust anchor (self-signed broker certificate)"
	fi

	local body
	if ! body=$("$JQ_BIN" -c --arg claim "$CLAIM_UUID" \
		'{nonce_id: .nonce_id, nonce: .nonce}
		 + (if $claim == "" then {} else {instance_uuid: $claim} end)' \
		<"$payload_file"); then
		die 4 "cannot build the redeem body from the bootstrap payload"
	fi

	local response="$WORK_DIR/response"
	local status
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
	local rc=$?
	set -e
	body=""

	if ((rc != 0)) || [[ -z "$status" || "$status" == "000" ]]; then
		sed -e 's/^/redeem: /' "$WORK_DIR/curl.err" >&2 || true
		log "verdict: TRANSPORT FAILURE — no HTTP status. With BROKER_CACERT unset this is usually the"
		log "         self-signed-anchor case failing chain or hostname validation: supply the spike CA"
		log "         in BROKER_CACERT, set BROKER_TLS_HOSTNAME to the certificate's SAN, or set"
		log "         ALLOW_INSECURE_TLS=1 deliberately."
		log "RESULT mode=redeem outcome=error status=000 nonce_id=$NONCE_ID reason=transport_failure"
		exit 15
	fi

	log "redeem: HTTP $status"

	if body_leaks_secret "$response"; then
		warn "the broker response contained the nonce value. Body WITHHELD: Appendix D forbids a nonce"
		warn "value in any response body beyond the guest delivery, in a log, or in evidence."
		log "RESULT mode=redeem outcome=leak status=$status nonce_id=$NONCE_ID reason=response_echoed_secret"
		exit 14
	fi

	local reason
	reason=$(json_field "$response" error reason code message)

	case "$status" in
	200 | 201)
		# The P8 redeem answer is binding metadata plus the frozen incus:
		# selectors; no key material. spiffe_id is reported when a later phase
		# starts returning one. Selectors and UUIDs are permitted evidence
		# (Appendix D rule 3).
		local resolved_uuid resolved_name resolved_generation resolved_project selectors spiffe_id
		resolved_uuid=$(json_field "$response" instance_uuid uuid)
		resolved_name=$(json_field "$response" instance_name name)
		resolved_generation=$(json_field "$response" generation generation_uuid)
		resolved_project=$(json_field "$response" project)
		spiffe_id=$(json_field "$response" spiffe_id spiffeId)
		selectors=$("$JQ_BIN" -r '[(.selectors? // [])[] | tostring] | join(",")' <"$response" 2>/dev/null || printf '')
		log "verdict: GRANTED $status"
		log "  resolved_instance_uuid=${resolved_uuid:-<absent>}"
		log "  resolved_instance_name=${resolved_name:-<absent>}"
		log "  resolved_generation=${resolved_generation:-<absent>}"
		log "  project=${resolved_project:-<absent>}"
		log "  selectors=${selectors:-<absent>}"
		[[ -n "$spiffe_id" ]] && log "  spiffe_id=$spiffe_id"
		log "RESULT mode=redeem outcome=granted status=$status nonce_id=$NONCE_ID instance_uuid=${resolved_uuid:--} instance_name=${resolved_name:--} generation=${resolved_generation:--} project=${resolved_project:--} spiffe_id=${spiffe_id:--} selectors=${selectors:--}"
		return 0
		;;
	esac

	diagnose_status "$status"
	log "RESULT mode=redeem outcome=rejected status=$status nonce_id=$NONCE_ID reason=${reason:--}"
	exit "$STATUS_EXIT"
}

# --- Main ---------------------------------------------------------------------

usage() {
	cat <<'EOF'
usage: guest-bootstrap.sh

Runs as root inside a spike guest. Every knob is an environment variable:

  MODE=redeem|fetch        redeem (default) posts the nonce to the broker;
                           fetch only reports and optionally stages the payload
  PAYLOAD_FILE=PATH        read the payload from PATH instead of /dev/incus/sock
  PAYLOAD_OUT=PATH         persist the raw payload to PATH (mode 0600)
  CLAIM_UUID=UUID          add an untrusted instance_uuid claim to the request
  GUEST_SOCKET=PATH        default /dev/incus/sock
  BOOTSTRAP_KEY=KEY        default user.spiffe-bootstrap
  BROKER_URL_OVERRIDE=URL  override the payload's broker_url
  REDEEM_PATH=PATH         default /v1alpha1/redeem
  BROKER_CACERT=PATH       spike CA for chain validation (recommended)
  BROKER_TLS_HOSTNAME=NAME certificate SAN to validate against
  ALLOW_INSECURE_TLS=1     explicit opt-in: disable curl chain validation
  CURL_BIN JQ_BIN OPENSSL_BIN CONNECT_TIMEOUT MAX_TIME

No mode ever prints the nonce value; see the secret-handling note at the top.
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

	case "$MODE" in
	redeem | fetch) ;;
	*) die 2 "MODE must be redeem or fetch, got: $MODE" ;;
	esac

	require_tool "$CURL_BIN" curl CURL_BIN
	require_tool "$JQ_BIN" jq JQ_BIN
	require_tool "$OPENSSL_BIN" openssl OPENSSL_BIN

	WORK_DIR=$(mktemp -d)
	trap cleanup EXIT

	# The payload never enters a shell variable: it is the secret carrier, and a
	# variable is one careless expansion away from a transcript. It lives only in
	# this 0600 file, and only jq ever reads it.
	local staged="$WORK_DIR/bootstrap.json"
	local source="socket"
	if [[ -n "$PAYLOAD_FILE" ]]; then
		[[ -r "$PAYLOAD_FILE" ]] || die 3 "PAYLOAD_FILE is not readable: $PAYLOAD_FILE"
		source="staged-file"
		log "source: staged payload $PAYLOAD_FILE (the guest socket was not read)"
		cat -- "$PAYLOAD_FILE" >"$staged"
	else
		read_payload_to_file "$staged"
	fi

	[[ -s "$staged" ]] || die 4 "the bootstrap value is empty"

	local digest
	digest=$(sha256_stdin <"$staged")

	if ! "$JQ_BIN" -e 'type == "object"' >/dev/null 2>&1 <"$staged"; then
		# The payload itself is never printed: it is the secret carrier.
		log "RESULT mode=$MODE outcome=error status=- nonce_id=- payload_sha256=$digest reason=payload_not_json"
		die 4 "the bootstrap value is not a JSON object (payload withheld; sha256=$digest)"
	fi

	NONCE_ID=$(json_field "$staged" nonce_id)
	local broker_url fingerprint secret_present=0
	broker_url=$(json_field "$staged" broker_url)
	fingerprint=$(json_field "$staged" broker_fingerprint)

	# The secret is copied into its own 0600 file, used only as the grep pattern
	# that withholds a leaking response body. The request body is built by jq
	# straight from $staged, so no code path here holds the value.
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
		log "RESULT mode=$MODE outcome=error status=- nonce_id=${NONCE_ID:--} payload_sha256=$digest reason=missing_fields"
		die 4 "the bootstrap payload is missing: ${missing[*]}"
	fi

	if [[ -n "$PAYLOAD_OUT" ]]; then
		cat -- "$staged" >"$PAYLOAD_OUT"
		log "staged: wrote the raw payload to $PAYLOAD_OUT (mode 0600, root only)"
	fi

	if [[ "$MODE" == "fetch" ]]; then
		log "RESULT mode=fetch outcome=ok source=$source nonce_id=$NONCE_ID payload_sha256=$digest broker_url=$broker_url broker_fingerprint=$(normalize_fingerprint "$fingerprint")"
		return 0
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
	redeem "$staged" "$host" "$port"
}

NONCE_ID="-"
SECRET_FILE=""
STATUS_EXIT=14
PINNED_LEAF=""
PINNED_SPKI=""

main "$@"

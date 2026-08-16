#!/bin/bash
# P5 final adversarial matrix, run against the authorization scriptlet.
# Usage: matrix2.sh <identity-name>
# A throwaway victim instance must already exist (created by admin) so that
# delete can be tested without ever targeting spike-authz-probe.
ID="$1"
export INCUS_CONF="$HOME/.spike-incusos-creds/$ID/conf"
UUID="6d1c5ee3-5b2f-4ead-8e54-db985302fbdb"
P="project=spike-spiffe"

run() {
  local label="$1"; shift
  echo "### CASE: $label"
  echo "\$ $*"
  out=$("$@" 2>&1); rc=$?
  echo "$out"
  echo "[exit=$rc]"
  echo
}

echo "########## IDENTITY: $ID (scriptlet authorization) ##########"
echo

echo "===== A. Intended attestor reads ====="
run "A1 resolve instance by volatile.uuid" \
  incus query "ovh:/1.0/instances?recursion=1&$P&filter=config.volatile.uuid%20eq%20$UUID"
run "A2 GET single instance record" \
  incus query "ovh:/1.0/instances/spike-authz-probe?$P"
run "A3 list instances (CLI)" \
  incus list ovh: --project spike-spiffe

echo "===== B. Intended bootstrap write (raw PATCH, no read) ====="
run "B1 PATCH set user.spiffe-bootstrap" \
  incus query -X PATCH "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"config":{"user.spiffe-bootstrap":"tok-'"$ID"'"}}'
run "B2 PATCH clear user.spiffe-bootstrap" \
  incus query -X PATCH "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"config":{"user.spiffe-bootstrap":""}}'

echo "===== C. Identity-anchor spoofing (P6 finding: volatile.uuid is writable) ====="
run "C1 PATCH volatile.uuid" \
  incus query -X PATCH "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"config":{"volatile.uuid":"00000000-0000-0000-0000-0000000000ff"}}'
run "C2 PATCH volatile.uuid.generation" \
  incus query -X PATCH "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"config":{"volatile.uuid.generation":"00000000-0000-0000-0000-0000000000ee"}}'
run "C3 PATCH security.privileged" \
  incus query -X PATCH "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"config":{"security.privileged":"true"}}'
run "C4 PATCH unrelated user.* key" \
  incus query -X PATCH "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"config":{"user.evil":"1"}}'

echo "===== D. Instance lifecycle and state ====="
run "D1 create instance" \
  incus create docker:debian:trixie ovh:spike-authz-newvictim --project spike-spiffe -c oci.entrypoint="sleep infinity"
run "D2 delete pre-created victim instance" \
  incus delete ovh:spike-authz-victim --project spike-spiffe --force
run "D3 DELETE victim via raw API" \
  incus query -X DELETE "ovh:/1.0/instances/spike-authz-victim?$P"
run "D4 stop probe (state change)" \
  incus query -X PUT "ovh:/1.0/instances/spike-authz-probe/state?$P" -d '{"action":"stop","timeout":5,"force":true}'
run "D5 exec into probe" \
  incus exec ovh:spike-authz-probe --project spike-spiffe -- /bin/true
run "D6 pull file from probe" \
  incus file pull ovh:spike-authz-probe/etc/hostname - --project spike-spiffe
run "D7 rename probe" \
  incus query -X POST "ovh:/1.0/instances/spike-authz-probe?$P" -d '{"name":"spike-authz-pwned"}'

echo "===== E. Cross-project (scriptlet must re-implement confinement) ====="
run "E1 GET protected instance in default project" \
  incus query "ovh:/1.0/instances/spire-server?project=default"
run "E2 list instances in default project" \
  incus list ovh: --project default
run "E3 list instances across all projects" \
  incus query "ovh:/1.0/instances?all-projects=true&recursion=1"
run "E4 GET instance in P6 project spike-uuid-lab" \
  incus query "ovh:/1.0/instances/lab-c2?project=spike-uuid-lab"
run "E5 list projects" \
  incus query "ovh:/1.0/projects"
run "E6 create project" \
  incus project create ovh:spike-authz-evil

echo "===== F. Host and server surface ====="
run "F1 host resources" \
  incus query "ovh:/1.0/resources"
run "F2 storage pools" \
  incus query "ovh:/1.0/storage-pools"
run "F3 trust store" \
  incus query "ovh:/1.0/certificates"
run "F4 set server config" \
  incus config set ovh: core.proxy_ignore_hosts=evil.example
run "F5 add trust certificate (escalation)" \
  incus config trust add-certificate ovh: "$HOME/.spike-incusos-creds/$ID/conf/client.crt" --name evil-escalation
run "F6 read server authorization scriptlet (self-inspection)" \
  incus query "ovh:/1.0" 

echo "===== G. Project-internal side surfaces ====="
run "G1 edit spike-spiffe project config" \
  incus project set ovh:spike-spiffe user.evil=1
run "G2 storage volumes in own project" \
  incus query "ovh:/1.0/storage-pools/local/volumes?$P&recursion=1"
run "G3 edit default profile in own project" \
  incus profile set ovh:default user.evil=1 --project spike-spiffe
run "G4 list images in own project" \
  incus query "ovh:/1.0/images?$P"
run "G5 read own certificate entry" \
  incus query "ovh:/1.0/certificates?recursion=1"
echo "########## END $ID ##########"

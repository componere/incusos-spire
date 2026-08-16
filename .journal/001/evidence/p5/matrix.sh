#!/bin/bash
# P5 adversarial matrix driver.
# Usage: matrix.sh <identity-name>
# Runs each case with the identity's own INCUS_CONF; never uses the admin credential.
ID="$1"
export INCUS_CONF="$HOME/.spike-incusos-creds/$ID/conf"
UUID="6d1c5ee3-5b2f-4ead-8e54-db985302fbdb"

run() {
  local label="$1"; shift
  echo "### CASE: $label"
  echo "\$ $*"
  out=$("$@" 2>&1); rc=$?
  echo "$out"
  echo "[exit=$rc]"
  echo
}

echo "########## IDENTITY: $ID ##########"
echo "## INCUS_CONF=$INCUS_CONF"
echo

echo "===== GROUP 1: intended reads (should ALLOW for attestor) ====="
run "R1 resolve instance by volatile.uuid in spike-spiffe" \
  incus query "ovh:/1.0/instances?recursion=1&project=spike-spiffe&filter=config.volatile.uuid%20eq%20$UUID"
run "R2 GET single instance record in spike-spiffe" \
  incus query "ovh:/1.0/instances/spike-authz-probe?project=spike-spiffe"
run "R3 list instances in spike-spiffe" \
  incus list ovh: --project spike-spiffe

echo "===== GROUP 2: bootstrap-key write (should ALLOW for writer only) ====="
run "W1 set user.spiffe-bootstrap in spike-spiffe" \
  incus config set ovh:spike-authz-probe user.spiffe-bootstrap=tok-$ID --project spike-spiffe
run "W2 read back user.spiffe-bootstrap" \
  incus config get ovh:spike-authz-probe user.spiffe-bootstrap --project spike-spiffe
run "W3 unset user.spiffe-bootstrap in spike-spiffe" \
  incus config unset ovh:spike-authz-probe user.spiffe-bootstrap --project spike-spiffe

echo "===== GROUP 3: writes beyond the grant (should DENY for both) ====="
run "X1 set unrelated user.* key (user.evil)" \
  incus config set ovh:spike-authz-probe user.evil=1 --project spike-spiffe
run "X2 set non-user config key (limits.memory)" \
  incus config set ovh:spike-authz-probe limits.memory=256MiB --project spike-spiffe
run "X3 set security.privileged" \
  incus config set ovh:spike-authz-probe security.privileged=true --project spike-spiffe
run "X4 rename instance" \
  incus rename ovh:spike-authz-probe spike-authz-probe-renamed --project spike-spiffe
run "X5 stop instance (state change)" \
  incus stop ovh:spike-authz-probe --project spike-spiffe --timeout 5
run "X6 exec into instance" \
  incus exec ovh:spike-authz-probe --project spike-spiffe -- /bin/true
run "X7 pull file from instance" \
  incus file pull ovh:spike-authz-probe/etc/hostname - --project spike-spiffe

echo "===== GROUP 4: instance lifecycle in own project (should DENY) ====="
run "L1 create instance in spike-spiffe" \
  incus create docker:debian:trixie ovh:spike-authz-victim --project spike-spiffe -c oci.entrypoint="sleep infinity"
run "L2 delete that instance (throwaway target, never the probe)" \
  incus delete ovh:spike-authz-victim --project spike-spiffe --force

echo "===== GROUP 5: cross-project access (should DENY) ====="
run "P1 list instances in default project" \
  incus list ovh: --project default
run "P2 GET protected instance in default project" \
  incus query "ovh:/1.0/instances/spire-server?project=default"
run "P3 list all projects" \
  incus query "ovh:/1.0/projects"
run "P4 list instances across all projects" \
  incus query "ovh:/1.0/instances?all-projects=true&recursion=1"
run "P5 create a new project" \
  incus project create ovh:spike-authz-evil
run "P6 read default project config" \
  incus query "ovh:/1.0/projects/default"

echo "===== GROUP 6: host / server surface (should DENY) ====="
run "H1 server info" \
  incus query "ovh:/1.0"
run "H2 host resources" \
  incus query "ovh:/1.0/resources"
run "H3 storage pools" \
  incus query "ovh:/1.0/storage-pools"
run "H4 cluster members" \
  incus query "ovh:/1.0/cluster/members"
run "H5 trust store (certificates)" \
  incus query "ovh:/1.0/certificates"
run "H6 set server config" \
  incus config set ovh: core.proxy_ignore_hosts=evil.example
run "H7 add a trust certificate" \
  incus config trust add-certificate ovh: "$HOME/.spike-incusos-creds/$ID/conf/client.crt" --name evil-escalation
run "H8 warnings" \
  incus query "ovh:/1.0/warnings"

echo "===== GROUP 7: project-internal side surfaces ====="
run "S1 edit project spike-spiffe config" \
  incus project set ovh:spike-spiffe user.evil=1
run "S2 list storage volumes in own project" \
  incus query "ovh:/1.0/storage-pools/local/volumes?project=spike-spiffe&recursion=1"
run "S3 edit default profile in own project" \
  incus profile set ovh:default user.evil=1 --project spike-spiffe
run "S4 list images in own project" \
  incus query "ovh:/1.0/images?project=spike-spiffe"
echo "########## END $ID ##########"

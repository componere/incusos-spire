# Incus 7.3 guest socket brief

## Decision

A guest can read `user.spiffe-bootstrap` from `GET /1.0/config/user.spiffe-bootstrap` over `/dev/incus/sock`. The value is returned as the exact configured string, with `Content-Type: application/octet-stream`; it is not wrapped in an Incus JSON response and the server does not append a newline. All `user.*` and `cloud-init.*` keys are visible. No other configuration namespace is visible. Configuration keys are guest-read-only: the guest cannot create, modify, or clear them through this API. A completed host-side `user.*` update is visible without restarting the instance, and a `config` event stream is available as an alternative to polling. Ordinary non-root guest processes cannot read the value: containers enforce guest UID 0 in the server handler, while VMs expose a root-owned mode-`0600` socket created by the root-running `incus-agent`.

The P8 guest-facing contract can therefore use the same operation for containers and VMs:

```http
GET /1.0/config/user.spiffe-bootstrap HTTP/1.1
Host: localhost
```

```sh
sudo curl --fail-with-body --silent --show-error \
  --unix-socket /dev/incus/sock \
  http://localhost/1.0/config/user.spiffe-bootstrap
```

Do not log or record this command's output. The output contains the bootstrap secret.

## Source baseline

The source baseline is the signed [`v7.3.0` tag](https://github.com/lxc/incus/releases/tag/v7.3.0), whose annotated tag resolves to commit [`90429bf42f08b41c091e799d81465ff24b5cee2b`](https://github.com/lxc/incus/commit/90429bf42f08b41c091e799d81465ff24b5cee2b). The recursive [Git tree API result at that commit](https://api.github.com/repos/lxc/incus/git/trees/90429bf42f08b41c091e799d81465ff24b5cee2b?recursive=1) locates the relevant implementations at `cmd/incusd/dev_incus.go`, `cmd/incus-agent/dev_incus.go`, `cmd/incus-agent/events.go`, and `internal/server/instance/drivers/agent-loader/`.

The live documentation is useful but tracks `main`, not the 7.3 tag. Source at the pinned commit controls where the two disagree.

## 1. Socket path and required processes

### Container

The path inside a container is exactly `/dev/incus/sock`. No guest agent is involved. Incus creates the host listener under its `guestapi` runtime directory and bind-mounts that directory at `/dev/incus` when `security.guestapi` is true or unset:

> `if util.IsTrueOrEmpty(d.expandedConfig["security.guestapi"]) {`
>
> `lxc.mount.entry ... dev/incus none bind,create=dir`

— Incus 7.3, [`internal/server/instance/drivers/driver_lxc.go` lines 991–996](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/driver_lxc.go#L991-L996)

The host-side listener path is `guestapi/sock`, and its mode is set to `0666`:

> `path := filepath.Join(dir, "guestapi", "sock")`
>
> `err = socketUnixSetPermissions(path, 0o666)`

— Incus 7.3, [`internal/server/endpoints/dev_incus.go` lines 10–39](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/endpoints/dev_incus.go#L10-L39)

Required state: `incusd` and the container must be running, and `security.guestapi` must not be false. The tagged documentation says:

> “`security.guestapi` must be set to `true` (which is the default) for an instance to allow access to the socket.”

— Incus 7.3, [`doc/dev-incus.md` lines 14–16](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/doc/dev-incus.md#L14-L16). The live [instance-options reference](https://linuxcontainers.org/incus/docs/main/reference/instance_options/#instance-security:security.guestapi) likewise lists `security.guestapi` as a boolean with default `true`.

`/dev/incus` is not a normal configurable instance device. The live [devices reference](https://linuxcontainers.org/incus/docs/main/reference/devices/) enumerates `none`, `nic`, `disk`, `unix-char`, `unix-block`, `usb`, `gpu`, `infiniband`, `proxy`, `unix-hotplug`, `tpm`, and `pci`; no guest-API device exists. The LXC driver creates the mount from `security.guestapi` instead. This is a negative finding: do not add a device to obtain the socket.

### VM

The path inside a VM is also exactly `/dev/incus/sock`, but the mechanism differs. `incus-agent` creates the local socket and proxies each request to the host over authenticated vsock. The agent source constructs `filepath.Join(dir, "incus", "sock")`; its caller passes `"/dev"`:

> `path := filepath.Join(dir, "incus", "sock")`
>
> `err = socketUnixSetPermissions(path, 0o600)`

— Incus 7.3, [`cmd/incus-agent/dev_incus.go` lines 264–304](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L264-L304)

> `DevIncusListener, err := createDevIncuslListener("/dev")`

— Incus 7.3, [`cmd/incus-agent/api_1.0.go` lines 115–151](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/api_1.0.go#L115-L151)

The VM therefore requires a running `incus-agent`; without it, `/dev/incus/sock` is not created. The live [VM creation documentation](https://linuxcontainers.org/incus/docs/main/howto/instances_create/#install-the-incus-agent-into-virtual-machine-instances) states:

> “The virtual machine images from the images remote are pre-configured to load that agent on startup.”
>
> “Incus provides the agent primarily through a remote `9p` file system with mount name `config`.”

That statement covers stock `images:debian/13` VM images. “Pre-configured” means that the persistent image contains the loader integration, not necessarily a fixed agent binary. The install script copies the udev rule, systemd unit, and setup helper into the guest and reloads systemd:

> `cp udev/99-incus-agent.rules ...`
>
> `cp systemd/incus-agent.service ...`
>
> `cp systemd/incus-agent-setup ...`
>
> `systemctl daemon-reload`

— Incus 7.3, [`internal/server/instance/drivers/agent-loader/install-linux.sh` lines 24–35](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/agent-loader/install-linux.sh#L24-L35)

At boot, the udev rule requests the service when the Incus virtio port appears:

> `ENV{SYSTEMD_WANTS}+="incus-agent.service"`

— Incus 7.3, [`internal/server/instance/drivers/agent-loader/systemd/incus-agent.rules` line 1](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/agent-loader/systemd/incus-agent.rules#L1)

The service runs the setup helper and then the host-supplied agent from `/run/incus_agent`:

> `ExecStartPre=TARGET/systemd/incus-agent-setup`
>
> `ExecStart=/run/incus_agent/incus-agent`

— Incus 7.3, [`internal/server/instance/drivers/agent-loader/systemd/incus-agent.service` lines 7–14](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/agent-loader/systemd/incus-agent.service#L7-L14)

The setup helper tries the `config` 9p share first, falls back to the `incus-agent` CD-ROM, copies the current agent payload to `/run/incus_agent`, and makes it root-owned:

> `mount_9p || mount_cdrom || fail`
>
> `cp -Ra "${PREFIX}.mnt/"* "${PREFIX}"`
>
> `chown -R root:root "${PREFIX}"`

— Incus 7.3, [`internal/server/instance/drivers/agent-loader/incus-agent-setup-linux` lines 11–53](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/agent-loader/incus-agent-setup-linux#L11-L53)

Thus a stock `images:debian/13` VM starts the agent automatically when the virtio port is detected; the host refreshes the runtime binary and credentials through the config share on every service start.

## 2. Read request and response shape

To enumerate visible keys:

```sh
sudo curl --fail-with-body --silent --show-error \
  --unix-socket /dev/incus/sock \
  http://localhost/1.0/config
```

The response is a JSON array of URL paths. If the bootstrap key exists, the array contains:

```json
[
  "/1.0/config/user.spiffe-bootstrap"
]
```

Other visible keys can appear in the same array, and order is not guaranteed because the 7.3 handler iterates a Go map. The source returns a JSON `[]string` built from matching expanded-config keys ([`cmd/incusd/dev_incus.go` lines 62–74](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L62-L74)).

To read the value, send the request shown in the Decision section. A successful local response has this shape:

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream

<exact configured string bytes>
```

There is no JSON envelope and no server-added newline. The 7.3 config handler returns the value with response type `raw` ([`cmd/incusd/dev_incus.go` lines 77–99](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L77-L99)); the raw renderer sets `application/octet-stream` and uses `fmt.Fprint` ([`internal/server/response/response.go` lines 68–81](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/response/response.go#L68-L81)). In a VM, the agent unwraps the host response and renders the same raw value ([`cmd/incus-agent/dev_incus.go` lines 88–117](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L88-L117), [lines 234–250](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L234-L250)).

If the allowed key is absent, the host returns HTTP 404 `not found`. If `security.guestapi` is false or the key is outside the two visible namespaces, it returns HTTP 403 `not authorized` ([`cmd/incusd/dev_incus.go` lines 77–96](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L77-L96)).

## 3. Visible configuration keys

Incus 7.3 uses a namespace-prefix allowlist:

```go
if strings.HasPrefix(k, "user.") || strings.HasPrefix(k, "cloud-init.") {
    filtered = append(filtered, fmt.Sprintf("/1.0/config/%s", k))
}
```

— Incus 7.3, [`cmd/incusd/dev_incus.go` lines 67–72](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L67-L72)

The per-key handler repeats the same check and rejects everything else:

```go
if !strings.HasPrefix(key, "user.") && !strings.HasPrefix(key, "cloud-init.") {
    return ... http.StatusForbidden ...
}
```

— Incus 7.3, [`cmd/incusd/dev_incus.go` lines 77–99](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L77-L99)

The VM agent independently repeats both prefix checks before proxying to the host ([`cmd/incus-agent/dev_incus.go` lines 59–117](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L59-L117)).

Therefore:

- Every expanded `user.*` key is visible, including `user.spiffe-bootstrap`.
- Every expanded `cloud-init.*` key is visible.
- There is no exact-key allowlist within those namespaces and no denylist exception. The only filter is the two prefix tests.
- Because the handler reads `ExpandedConfig()`, matching values inherited from profiles are visible as well as instance-local values.
- `volatile.*`, `security.*`, `raw.*`, and every other namespace are forbidden.

The tagged documentation agrees:

> “Currently only the `cloud-init.*` and `user.*` keys are accessible to the instance.”

— Incus 7.3, [`doc/dev-incus.md` lines 109–118](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/doc/dev-incus.md#L109-L118); same text in the live [`/dev/incus` documentation](https://linuxcontainers.org/incus/docs/main/dev-incus/#config).

## 4. Live changes and events

A host-side change to `user.spiffe-bootstrap` is visible after the host update completes; no instance restart is required. The live [instance-options reference](https://linuxcontainers.org/incus/docs/main/reference/instance_options/#instance-miscellaneous:user.*) marks `user.*` as `Live update: yes`.

The source confirms the update order. Both drivers first update the database, then, while the instance is running, emit a `config` event for each changed `user.*` key with `key`, `old_value`, and `value`:

> `// Send devIncus notifications only for user.* key changes`
>
> `if !strings.HasPrefix(key, "user.") { continue }`
>
> `"value": d.expandedConfig[key]`

— VM driver, [`internal/server/instance/drivers/driver_qemu.go` lines 7160–7224](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/driver_qemu.go#L7160-L7224); container driver, [`internal/server/instance/drivers/driver_lxc.go` lines 5588–5631](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/driver_lxc.go#L5588-L5631).

Each GET reads the current `ExpandedConfig()` rather than a boot-time snapshot ([`cmd/incusd/dev_incus.go` lines 62–99](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L62-L99)). The VM agent also performs a fresh host `RawQuery` for every local GET rather than caching values ([`cmd/incus-agent/dev_incus.go` lines 59–117](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L59-L117)).

A guest can watch changes without polling:

```sh
sudo curl --no-buffer --fail-with-body --silent --show-error \
  --unix-socket /dev/incus/sock \
  'http://localhost/1.0/events?type=config'
```

Without a WebSocket `Upgrade` header, 7.3 deliberately falls back to a never-ending HTTP event stream ([`cmd/incusd/dev_incus.go` lines 131–177](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L131-L177)). The stream sends HTTP 200 with `Content-Type: application/json` and newline-delimited JSON objects ([`internal/server/events/connections.go` lines 152–175](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/events/connections.go#L152-L175), [lines 218–232](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/events/connections.go#L218-L232)). A bootstrap update event has this schema, with the real configured string in `metadata.value`:

```json
{
  "timestamp": "<RFC3339 timestamp>",
  "type": "config",
  "metadata": {
    "key": "user.spiffe-bootstrap",
    "old_value": "<previous configured string>",
    "value": "<new configured string>"
  }
}
```

The event carries the secret and must not be logged. Events should be an optimization, not the only retrieval path: the VM driver silently drops notification delivery when the agent is offline ([`internal/server/instance/drivers/driver_qemu.go` lines 10504–10523](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/driver_qemu.go#L10504-L10523)). The guest should perform a GET at startup, then optionally watch `type=config` for rotation or clearing.

## 5. Guest writes and clearing

The guest cannot write or clear `user.spiffe-bootstrap` through `/dev/incus/sock`. The tagged documentation states:

> “At this time, there also aren't any instance-writable namespace.”

— Incus 7.3, [`doc/dev-incus.md` lines 109–118](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/doc/dev-incus.md#L109-L118)

The source has only read handlers for `/1.0/config` and `/1.0/config/{key}`; neither decodes a request body nor mutates config ([`cmd/incusd/dev_incus.go` lines 62–99](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L62-L99)). The VM agent hard-codes host method `GET` for both endpoints regardless of the local request method ([`cmd/incus-agent/dev_incus.go` lines 59–117](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L59-L117)).

The socket is not entirely read-only: `PATCH /1.0` can change the instance's `Ready`/`Started` state marker, but this is a separate endpoint and it writes only `volatile.last_state.ready` ([`cmd/incusd/dev_incus.go` lines 188–250](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L188-L250)). It cannot alter an instance config key.

A 7.3 footgun is that the config routes are not method-qualified. A `PATCH` or `DELETE` sent to `/1.0/config/{key}` may execute the read handler and return the current value rather than a clean 405, but it still cannot mutate or clear the key. Callers must use GET and must not interpret a non-GET 200 response as a successful write.

P8's single-use design therefore does not need to defend against guest-initiated config clearing. Only the host-side bootstrap writer can clear the key.

## 6. Identity information available to the guest

`GET /1.0` returns exactly four fields: `api_version`, `instance_type`, `location`, and `state`. The schema has no UUID, generation, instance name, or project:

> `APIVersion string json:"api_version"`
>
> `InstanceType string json:"instance_type"`
>
> `Location string json:"location"`

— Incus 7.3, [`shared/api/guest/dev_incus.go` lines 3–27](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/shared/api/guest/dev_incus.go#L3-L27); handler construction at [`cmd/incusd/dev_incus.go` lines 188–214](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L188-L214).

`GET /1.0/meta-data` does expose the instance name as `local-hostname`. It also exposes a cloud-init instance ID:

> `instance-id: %s`
>
> `local-hostname: %s`
>
> `inst.CloudInitID(), inst.Name()`

— Incus 7.3, [`cmd/incusd/dev_incus.go` lines 121–129](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L121-L129).

The cloud-init ID is not `volatile.uuid`. `CloudInitID()` reads `volatile.cloud-init.instance-id` and falls back to the instance name:

> `id := d.LocalConfig()["volatile.cloud-init.instance-id"]`
>
> `return d.name`

— Incus 7.3, [`internal/server/instance/drivers/driver_common.go` lines 239–247](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/driver_common.go#L239-L247).

A direct GET for `volatile.uuid` or `volatile.uuid.generation` is forbidden because neither key begins with `user.` or `cloud-init.` ([`cmd/incusd/dev_incus.go` lines 77–99](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L77-L99)). No endpoint returns the project name. These are negative source findings: `volatile.uuid`, generation, and project are absent from the response schema and filtered from config.

The guest can therefore learn:

- its instance name from `local-hostname`;
- its host/cluster-member location, instance type, and state from `/1.0`;
- its cloud-init ID, which is a distinct value and may merely equal the name;
- host-selected `user.*` values, including the bootstrap value.

It cannot learn its Incus UUID, generation UUID, or project through the stock guest API. It also cannot produce a UUID-bound proof by itself. For P8, possession of `user.spiffe-bootstrap` is the proof presented to the broker; the broker must retain and resolve the UUID/generation binding server-side. That proof is a bearer credential, not a cryptographic proof tied to the calling VM's transport.

## 7. Authentication, authorization, and non-root access

### Container security

The host socket has mode `0666`, so filesystem permissions alone do not protect it. Incus obtains `SO_PEERCRED`, maps the connecting PID to its container, computes that container's mapped root UID, and rejects any other UID:

> `cred := pidMapper.GetConnUcred(...)`
>
> `c, err := findContainerForPid(cred.Pid, s)`
>
> `if rootUID != cred.Uid {`
>
> `http.Error(w, "Access denied for non-root user", http.StatusUnauthorized)`

— Incus 7.3, [`cmd/incusd/dev_incus.go` lines 279–310](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L279-L310). Peer credentials are captured from the Unix connection in [`cmd/incusd/dev_incus.go` lines 313–367](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L313-L367).

Result: guest UID 0 can read the bootstrap value; an ordinary non-root container process can open the world-accessible socket inode but receives HTTP 401 before the config handler runs. The secret is root-only by server authorization, not by socket mode.

### VM security

The VM agent creates `/dev/incus/sock` with mode `0600` ([`cmd/incus-agent/dev_incus.go` lines 264–304](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L264-L304)). The systemd unit has no `User=` or `Group=` override ([`incus-agent.service` lines 7–14](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/agent-loader/systemd/incus-agent.service#L7-L14)); systemd documents that system services default to user `root` ([`systemd.exec` § `User=`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User=)). The socket is therefore created by UID 0, and only its owner has read/write bits.

Result: guest root can read the bootstrap value; an ordinary non-root VM process cannot connect to the socket. The agent's local handler has no additional peer-UID check, so the mode-`0600` Unix DAC boundary is the VM-side enforcement. A process with guest-root-equivalent DAC-bypass capability is not protected from the secret in either instance type.

The live documentation's statement that there is “no authentication support” refers to the HTTP protocol: there is no token, client certificate, or login supplied by the guest caller ([live protocol section](https://linuxcontainers.org/incus/docs/main/dev-incus/#protocol)). It does not mean arbitrary guest users are allowed. Container peer-credential authorization and VM filesystem permissions operate below HTTP.

**Security answer for P8:** under the Incus 7.3 defaults, a normal non-root guest service cannot read `user.spiffe-bootstrap`. The guest bootstrap client must run as root or have a narrowly designed privileged helper. All guest root processes share access; `/dev/incus/sock` does not isolate one root service from another.

## 8. Incus 7.3 footguns and documentation mismatches

1. **The live docs track `main`, not 7.3.** Use commit `90429bf42f08b41c091e799d81465ff24b5cee2b` for the P8 contract. The tagged source and tagged `doc/dev-incus.md` agree on key visibility and lack of writable namespaces.

2. **The documented host-socket architecture describes containers, not VMs.** The docs say, “This socket is then exposed into every single instance” ([tagged `doc/dev-incus.md` lines 20–25](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/doc/dev-incus.md#L20-L25)). In a VM, the agent instead creates a distinct local `/dev/incus/sock` and proxies over vsock ([`cmd/incus-agent/dev_incus.go` lines 44–117](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L44-L117), [lines 264–304](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L264-L304)).

3. **The documented `SO_PEERCRED` authentication explanation is container-only.** The docs say Incus “extract[s] the initial socket's user credentials” ([tagged `doc/dev-incus.md` lines 30–35](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/doc/dev-incus.md#L30-L35)). That is true for containers. VMs rely on the agent's mode-`0600` local socket and the agent-to-host authenticated transport.

4. **The events documentation says “WebSocket upgrade,” but 7.3 also supports plain HTTP streaming.** The tagged docs describe only WebSocket ([`doc/dev-incus.md` lines 163–179](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/doc/dev-incus.md#L163-L179)); the host and VM agent sources explicitly fall back to a stream when no upgrade header is present ([`cmd/incusd/dev_incus.go` lines 145–177](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incusd/dev_incus.go#L145-L177), [`cmd/incus-agent/events.go` lines 31–76](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/events.go#L31-L76)). This is why the copy-pasteable `curl --no-buffer` watcher works.

5. **The metadata docs label the endpoint “Container meta-data,” but the VM agent proxies it too.** The VM implementation contains `DevIncusMetadataGet` and forwards `/1.0/meta-data` to the host ([`cmd/incus-agent/dev_incus.go` lines 120–146](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/cmd/incus-agent/dev_incus.go#L120-L146)).

6. **A non-GET config request is not a write and might not fail cleanly.** The route patterns are not method-qualified, and the VM agent itself hard-codes upstream GET. Do not use PATCH/DELETE response status as evidence of mutation; re-read with GET if testing this behavior.

7. **Events are not a durable delivery mechanism.** In particular, the VM driver treats an offline agent as a non-error and drops the event ([`driver_qemu.go` lines 10504–10523](https://github.com/lxc/incus/blob/90429bf42f08b41c091e799d81465ff24b5cee2b/internal/server/instance/drivers/driver_qemu.go#L10504-L10523)). Always GET the current key before subscribing.

## Unknowns and required live confirmation

The source fixes the API contract, filtering, modes, and startup design. Two artifact/runtime facts remain **[UNVERIFIED]** because this research wave was explicitly prohibited from touching the live Incus host:

1. **[UNVERIFIED] The particular currently published `images:debian/13` VM artifact contains the documented loader integration and reaches active `incus-agent` state on the P8 host.** The official docs say all VM images from `images:` are preconfigured, but only a launch of that exact artifact settles packaging or image-regression risk. Live experiment:

   ```sh
   incus launch images:debian/13 p8-guest-sock-check --vm
   incus exec p8-guest-sock-check -- systemctl is-active incus-agent
   incus exec p8-guest-sock-check -- test -S /dev/incus/sock
   incus exec p8-guest-sock-check -- curl --fail --silent --show-error \
     --unix-socket /dev/incus/sock http://localhost/1.0
   ```

   Expected results: `active`, successful socket test, and JSON with `instance_type` equal to `virtual-machine`. Do not set or print the real bootstrap value in this preliminary check.

2. **[UNVERIFIED] The observed socket owner/group on the target host and guest match the creator credentials implied by source.** Incus explicitly sets modes but does not call `chown` on either socket. Settle the complete mode/ownership record with:

   ```sh
   stat -Lc '%a %U:%G %n' /dev/incus/sock
   ```

   Expected source-derived modes are `666` in a container and `600` in a VM. Run the command inside each instance. This check does not expose a bootstrap value.

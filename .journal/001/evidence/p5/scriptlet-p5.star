# P5 least-privilege authorization scriptlet for Incus 7.3.
#
# Routed via:  incus config set <remote>: authorization.client.tls-restricted=scriptlet
#
# Unrestricted TLS clients (the admin certificate) and the local unix socket
# keep their built-in "allow" route and are NEVER evaluated by this function.
# Built-in routing observed in Incus 7.3 docs and confirmed live:
#   unix=allow, tls=allow, tls-restricted=tls, oidc=allow, default=deny
#
# WARNING (verified live): routing tls-restricted away from the "tls" driver
# stops Incus from enforcing the per-certificate project list. This scriptlet
# therefore re-implements project confinement itself, and additionally
# requires that the certificate still be admin-marked restricted to the
# project it is acting on.
#
# Object formats observed live on this server:
#   server:incus
#   project:<project>
#   instance:<project>/<name>
#   image:<project>/<fingerprint>
#   profile:<project>/<name>
#   storage_volume:<project>/<pool>/<type>/<name>
#   certificate:<fingerprint>

PROJECT = "spike-spiffe"

def authorize(details, object, entitlement):
    cert = details.Certificate
    name = cert.name

    # Defence in depth: only act on certificates the admin actually marked
    # restricted to PROJECT. A name alone never grants anything.
    if not cert.restricted:
        return False
    if PROJECT not in cert.projects:
        return False

    instance_prefix = "instance:" + PROJECT + "/"

    # GET /1.0 is the client handshake. Denying this breaks every request,
    # including the intended ones, so it is irreducible.
    handshake = object == "server:incus" and entitlement == "can_view"

    # Read-only attestor: resolve instance UUID -> verified metadata.
    if name == "spike-attestor-ro":
        if handshake:
            return True
        return object.startswith(instance_prefix) and entitlement == "can_view"

    # Bootstrap writer: write-only. Incus passes only (object, entitlement)
    # and never the request body, so a single-config-key grant CANNOT be
    # expressed. can_edit is the smallest entitlement that permits the
    # user.spiffe-bootstrap mutation.
    if name == "spike-bootstrap-writer":
        if handshake:
            return True
        return object.startswith(instance_prefix) and entitlement == "can_edit"

    # Any other restricted certificate routed here gets nothing.
    return False

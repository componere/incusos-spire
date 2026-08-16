def authorize(details, object, entitlement):
    name = details.Certificate.name
    instance_prefix = "instance:spike-spiffe/"
    if name == "spike-attestor-ro":
        return object.startswith(instance_prefix) and entitlement == "can_view"
    if name == "spike-bootstrap-writer":
        return object.startswith(instance_prefix) and entitlement == "can_edit"
    return False

def authorize(details, object, entitlement):
    # Discovery only: log every authorization question Incus asks for a
    # restricted TLS client, then allow. Never left enabled.
    log_info("P5DISCOVERY user=", details.Username, " proto=", details.Protocol,
             " project=", details.ProjectName, " object=", object,
             " entitlement=", entitlement)
    return True

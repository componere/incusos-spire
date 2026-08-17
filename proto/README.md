# Protobuf schemas

Regenerate Go bindings from the repository root:

```sh
protoc --go_out=. --go_opt=module=github.com/componere/incusos-spire -I proto proto/componere/incus/v1alpha1/reference.proto
```

Generator versions used for the checked-in output:

- `protoc --version` → `libprotoc 33.4`
- `protoc-gen-go --version` → `protoc-gen-go v1.36.10`

Generated files are never hand-edited.

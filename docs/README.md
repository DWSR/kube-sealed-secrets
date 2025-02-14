# Sealed Secrets

## Description

Sealed Secrets is a project that uses asymmetric encryption to safely store secrets in Git and then
decrypt them once they are applied to a cluster.

More info [here](https://github.com/bitnami-labs/sealed-secrets).

## Repo Layout

```text
.
├── base <-- base resources and patches that are version-agnostic
├── docs <-- documentation
├── overlays <-- use-case specific resources and patches (e.g. testing)
├── test <-- E2E tests to help assert behaviour between versions
└── upstream <-- Vendored copies of versions of the upstream installation
```

## Updating Versions

1. Add the new verison to `vendir.yml` as well as an inline Kustomization that inflates it.
1. Run `vendir sync` to inflate the new version.
1. Bump `overlays/live` or `overlays/test` to use the new version

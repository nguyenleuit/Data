# Build Policy

Test labs should be rebuilt from public CVE, NVD, vendor, and upstream references.

Each rebuilt case uses this layout:

```text
cases/<severity>/<CVE>/
  manifest.yml
  public_task.yml
  eval.yml
  compose.yml
  target/
  auxiliary/
  oracle/
  artifacts/
```

## Fidelity Levels

Use only these `fidelity.level` values:

- `faithful`: runs the real vulnerable upstream product or a pinned upstream build with only minimal harnessing.
- `near-faithful`: uses a product/component-specific fixture or partial harness backed by pinned upstream source, advisory, patch, or release references.
- `cve-specific-emulated`: uses a deterministic local reproduction of the documented CVE attack surface without running upstream product code.

Every non-faithful case must list concrete limitations in `manifest.yml`.

## Fixed Controls

Use only these `status.fixed_control` values:

- `present`: a non-vulnerable target/control is available and the hidden oracle performs a negative check.
- `deferred`: no fixed control is available yet.
- `not-required-for-train`: train-only cases where a fixed control is intentionally out of scope.

When `status.fixed_control: present`, `runtime.fixed_control` must declare the fixed service, mode, and target details for hidden validation. Public tasks must continue to expose only the vulnerable target.

Build requirements:

- Prefer real vulnerable upstream releases over fixtures where practical.
- Record source URLs and artifact references in `manifest.yml`.
- Keep exploit triggering external and explicit.
- Keep evaluated frameworks isolated from `oracle/`, `solution/`, `eval.yml`, and `artifacts/`.
- Bind exposed services to `127.0.0.1` unless a runner provides an isolated network.
- Avoid hardcoded success tokens in public task material.

---
type: instructions
---

Build git-install as a portable Git extension. Keep the provider-independent
core separate from future host adapters. Discovery is read-only and must never
execute repository code. Remote repositories use temporary shallow clones of
their default branch and are always cleaned up. Pin remote work to a resolved
commit SHA. Keep CLI output usable by people and scripts, test safety behavior,
and document non-obvious safety decisions near the code.

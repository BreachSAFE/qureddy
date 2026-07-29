# QuReddy agent rules

## Canonical source and release authority

`https://github.com/breachsafe/qureddy` is the only canonical QuReddy Git
source. Use its public `breachsafe-qureddy` package artifacts. Do not use a
personal-namespace mirror, a legacy local checkout, or an alternate remote as
source, fallback, evidence, or publication target.

Before a release-related change, distinguish these facts explicitly:

1. canonical Git revision;
2. published wheel version and SHA-256; and
3. OCI image digest, when applicable.

They are related, but none proves another. Do not infer a released wheel from
the current Git branch.

The CI provenance gate is mandatory. Do not weaken, bypass, or add an allow
list to it; correct the provenance instead.

# Example Outcomes

These examples describe verdict semantics. They are not reports from a real
installation and contain no production data.

## BLOCKED

The target package adds or changes a lifecycle script, the declared Node
runtime cannot satisfy `engines.node`, a required customization anchor is
missing, or the installation coverage profile is incomplete. The rehearsal
stops. The operator gets the failed evidence item and the affected surface, but
no update is attempted.

## READY_FOR_OPERATOR_PLAN

Exact archives passed integrity checks, package metadata risks were evaluated,
every declared customization contract passed, and every required installation
surface has an explicit post-upgrade check. The generated operator plan still
stops before apply. It is preparation for a maintenance-window decision, not
permission to update.

## What remains unproven

Until an approved update has happened, the post-upgrade E2E checks remain
`not_run`. The kit never rewrites that state to green based on package evidence.

`local-installation.observation.json` is a path-bearing local input template.
Replace every placeholder on the machine being attested. Its paths are never
copied to the public-safe attestation output.

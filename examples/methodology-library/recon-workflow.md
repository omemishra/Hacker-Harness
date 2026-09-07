---
hackerHarness:
  strict: true
  requirements:
    commands:
      - curl
---
# Recon workflow

## Stage 1: Authorization and target normalization

Read the active scope, normalize the supplied target, identify exclusions, and establish stop conditions. Do not send network requests in this stage.

## Stage 2: Passive discovery

Use passive evidence already present in the project and approved passive sources. Record discovered assets as candidates; do not assume they are authorized.

## Stage 3: Evidence summary

Consolidate the authorized observations, separate confirmed evidence from hypotheses, and provide a handoff for later validation.

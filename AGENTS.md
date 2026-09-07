# Agent development instructions

- This repository implements an authorization-aware security-testing harness. Preserve authorization checks in the tool layer; prompt warnings are supplementary only.
- Never add default workflows that perform active testing without a human approval node and an explicit target input.
- Keep file operations confined to the project root and keep scope, config, and state operator-controlled.
- Add offline tests for every policy change and run `python -m unittest discover -s tests -t . -v`.
- Do not add telemetry or store provider keys in project state.

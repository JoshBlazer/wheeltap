# Fixtures

Three directories, three different jobs.

## `vulnerable/`

Code that **must be flagged**, one directory per rule
(`WT001_missing_signer/`, ...). Written before the detector it exercises.

A vulnerable fixture has to look like code someone would actually ship. A
fixture that announces its own bug proves nothing — the detector needs to find
the hazard in plausible surroundings, not in a labelled example.

## `safe/`

Code that **must not be flagged by any rule**. This is the more important
directory, and the harder one to write.

Each detector ships with at least two safe fixtures chosen specifically to break
a naive implementation of it: the validation done one line later, the constraint
expressed a different but equivalent way, the arithmetic that genuinely cannot
overflow. Getting these wrong is how a security tool gets switched off.

The no-false-positive assertion runs **globally** — every rule against every safe
fixture — not per rule. Cross-detector false positives are the ones that survive
otherwise.

## `corpus/`

Real third-party programs, vendored unmodified, for end-to-end scanning and
benchmarking. See `corpus/README.md` for attribution and licences.

---

None of this is compiled: the workspace manifest excludes `fixtures/`. Some
vulnerable fixtures will not compile, by design.

**Never weaken a fixture to silence a false positive.** Fix the detector.

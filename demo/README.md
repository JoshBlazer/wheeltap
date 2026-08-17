# Demo

A small, correct Anchor vault program, and a workflow that scans it with the
Wheeltap Action on every pull request that touches this directory.

It exists to be broken. A pull request that adds a plausible-looking withdraw
instruction with a missing signer check gets the finding back as an inline
annotation on the diff, which is the clearest available answer to "what does
this actually do for me".

On `main` it reports nothing. That matters as much as the finding does: a
scanner that flags ordinary code teaches people to ignore it.

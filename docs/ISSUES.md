# Issues

Use the regular issue template for build failures, portability bugs, test gaps, and documentation corrections.

## What to include

- The repository revision
- The exact command that failed
- The exact error output
- The host OS and compiler
- Whether the issue reproduces in Debug and Release

## Security issues

Security-sensitive reports do not belong in public issues. Follow [SECURITY.md](SECURITY.md).

## What is in scope

- Incorrect return codes
- Broken test vectors
- Build and package regressions
- Documentation mismatches with verified behavior

## What is not a release claim

- Unsupported platforms that were not verified
- Unrun toolchains
- Side-channel or protocol safety beyond what the repository explicitly states

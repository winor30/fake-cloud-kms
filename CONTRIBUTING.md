# Contributing

Thanks for helping improve Fake Cloud KMS. Keep changes focused and tested.

## Quick workflow
- Go 1.25+ (use the version in `go.mod`).
- Before opening a PR, run: `make fmt vet lint test build`.
- Keep PRs scoped and roughly under 400 LOC; add tests for any code you change.

## Code style
- Keep module layout: CLI in `cmd/fake-cloud-kms`, core logic in `service/`, storage in `store/`, crypto in `kmscrypto/`, transport in `transport/grpc/`, public helpers in `pkg/`.
- Do not edit generated protobufs or mocks.
- Follow Go idioms: tab indent, document exported identifiers, return `nil` for empty slices.
- Resource names must stay Cloud KMS-compatible; avoid TODOs—document non-support in README/docs instead.

## Testing
- Prefer table-driven unit tests for new logic and edge cases.
- Use real crypto paths; mock only external services or hard-to-trigger failures.
- If API behavior changes, adjust integration-style tests (Testcontainers harnesses in `clients/` or `pkg/api/emulator`) as needed.

## Docs
- Update README/docs when adding flags, behaviors, or support matrix changes.

## PR checklist
- State motivation and scope.
- List commands/tests you ran.
- Note any limitations or follow-ups.

## Code of Conduct
Be respectful and constructive; harassment or discrimination is not tolerated.

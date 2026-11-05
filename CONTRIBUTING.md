# Contributing to PegaProx

PegaProx is built and maintained by a small volunteer team, and we genuinely appreciate
contributions. A little structure keeps them reviewable — here's what gets a PR merged.

## Before you open a PR

- **Open an issue first** for anything non-trivial, and let us confirm the direction. Large,
  unsolicited PRs that nobody asked for are the ones most likely to be closed unread.
- **Keep it focused — one PR, one concern.** Don't bundle a security fix, a feature and a refactor
  into a single change; we can't review or revert them independently, so the whole thing stalls.

## The quality bar

- **Test it yourself, and say how.** In the PR, describe the actual scenario/cluster you ran it
  against, with output. "The CI is green" is not evidence that a behaviour change to a core path
  works.
- **Design for scale.** PegaProx runs against clusters with hundreds of nodes and thousands of VMs.
  Code that loads the whole user or VM set on a hot path, or does per-item work inside a broadcast
  loop, will not be merged — measure it at that scale, not on a two-VM lab.
- **Write it like the rest of the code.** Small, hand-written, in the style of the surrounding files.

## AI-assisted contributions

Using an AI assistant is completely fine. Submitting its output without reading, understanding and
testing it is not. The tell-tale signs — a verbose auto-generated description, unrelated changes
bundled together, plausible-but-wrong logic, scale mistakes a person would have felt — get a PR
closed. If you used AI, **you own every line**: review and test it as if you had written it by hand.
Name the assistant or model you used on the "AI tool / model used" line of the pull request
template. We record it for licensing and compliance review.

## What happens next

- We develop on the `Testing` branch and fast-forward `main` only at release. PRs opened against
  `main` are automatically retargeted onto `Testing`.
- Every PR runs the test suite, and a maintainer reviews it before merge. A clean, focused, tested
  PR against a discussed issue merges quickly. An unfocused PR, or unreviewed AI output, will be
  asked to be reworked — or closed.

Thanks for helping keep PegaProx healthy. 💙

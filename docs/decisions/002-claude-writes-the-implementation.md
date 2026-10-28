# DR-002: Claude writes the implementation

- Date: 2026-10-18
- Status: Accepted. Decided by the owner.
- Affects: The work rules in CLAUDE.md.

## Before

The owner wrote the code. Claude reviewed it and explained the security reasons.

## After

Claude writes the code and its tests in small steps that follow the roadmap. Claude explains the reason for each security choice, so the owner can defend it.

## Reason

The owner wants more progress and still wants to understand each choice.

## Consequences

Each step has tests and a written reason. Claude asks before it changes a recorded decision. Since 2026-10-19, Claude commits each tested step. Since 2026-10-22, Claude also pushes it.

# DR-012: pnpm replaces npm for the Angular workspace

- Date: 2026-10-31
- Status: Accepted. The owner asked for pnpm in all projects. Claude made the change with the owner's go-ahead.
- Affects: U8 (changed).

## Before

U8 said that `package-lock.json` is committed, that CI installs with `npm ci --ignore-scripts`, and that CI runs `npm audit`.

## After

`ui/pnpm-lock.yaml` is committed. CI and the Dockerfile install with `pnpm install --frozen-lockfile --ignore-scripts`. CI runs `pnpm audit --audit-level low`. The `packageManager` field in `ui/package.json` names the pnpm version. The vite override moved from `package.json` to `ui/pnpm-workspace.yaml`.

## Reason

pnpm keeps one copy of each package version in a store and links it into each project. The owner's projects share many packages, and npm stored a full copy in each project. pnpm also refuses an import of a package that `package.json` does not list. The controls of U8 stay the same: a committed lockfile, no install scripts from dependencies, and an audit that fails CI.

`pnpm import` made the lockfile from `package-lock.json`. The set of package versions is the same as before (410 packages).

## Consequences

A developer needs pnpm at the pinned version. CI installs it with `pnpm/action-setup`, pinned to a commit SHA. Dependabot reads `pnpm-lock.yaml` in the same `npm` ecosystem entry.

# Buzz

Desktop chat shell with:

- Tauri + React + TypeScript + Vite
- Tailwind CSS
- shadcn/ui-ready shared components
- Biome (lint/format/check)
- Feature-driven frontend structure

## Joining a DNTLS community

Communities that require admin approval show **Waiting for approval** before
profile setup. Buzz checks again about every five seconds. Once approved, it
publishes your verified DNTLS name and opens the community automatically.
A later install of an already-approved name enters the same way, with no
waiting screen. An admin rejection shows **Request declined**, without
invitation or key-recovery hints.

Pending approval responses during profile lookup, publishing, or other
onboarding requests return to the same waiting screen.

## Scripts

- `pnpm dev` - run the web frontend
- `pnpm tauri dev` - run the desktop app
- `pnpm build` - typecheck and build frontend
- `pnpm typecheck` - TypeScript checks
- `pnpm lint` - Biome lint
- `pnpm format` - Biome format (write)
- `pnpm check` - Biome check

The admission regression scenarios use the desktop frontend with mocked native
commands and relay responses:

```sh
pnpm build:e2e
pnpm exec playwright install chromium
pnpm exec playwright test --project=integration tests/e2e/dntls-onboarding-approval.spec.ts
```

## Structure

- `src/shared` - reusable app-wide code (`ui`, `lib`, `styles`)
- `src/features` - feature modules (vertical slices)
- `src/app` - top-level app composition

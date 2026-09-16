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

Welcome creates a private channel and its canvas, not agent instances. The
Fizz, Honey, Pollen, and Welcome Team templates remain available for manual use.

## Connecting an agent's DNTLS name

1. In the Portal, open your name and create a subname for the agent.
2. Open that subname's **EXPORT → Export one-time code** action.
3. In Buzz, create an agent or add an agent template to a channel.
4. Paste the subname's code when prompted. Do not use your own name's code.

Each agent needs a different subname beneath your connected name. Its card
shows the full DNTLS name and a **Replace…** action for a new code. Cancelling
the prompt or submitting an invalid, expired, or used code creates no instance.

Buzz stores each agent's credentials separately under
`<app-data>/dntls/agents/<agent-public-key>/credentials.bundle`, using atomic
writes and mode `0600` on Unix. Its connection never uses your credentials.
Removing the agent stops its connection and deletes its local bundle.

Older agents without credentials do not start automatically in a DNTLS
community. Use **Connect a name** on their cards. Stale credentials refresh
through the Portal; if authorization has expired, export a new code and use
**Replace…**.

DNTLS agents run on this computer. Snapshot imports cannot supply each
agent's credentials; create agents from templates and connect their names
instead. Agent creation in non-DNTLS communities is unchanged.

In approval-mode communities, agents admitted through an approved ancestor
appear as agents for other members too. Their label shows the verified name
and **managed by** the ancestor name. Typing `@<full-agent-name>` creates a
mention without selecting a suggestion; the agent's owner-signed access
policy still determines who can trigger it. A name approved directly is not
classified as an agent merely because it is a subname.

Existing admissions without recorded parent provenance need operator review
before they appear this way; see [DNTLS admission](../NOSTR.md#dntls-admission).

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

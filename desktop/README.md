# Buzz

Desktop chat shell with:

- Tauri + React + TypeScript + Vite
- Tailwind CSS
- shadcn/ui-ready shared components
- Biome (lint/format/check)
- Feature-driven frontend structure

## Joining a DNTLS community

Buzz asks for your DNTLS name before anything else. On first run the
**Connect your DNTLS name** step follows "Create a new identity key": paste
the one-time code from your name's page in the DNTLS Portal (**EXPORT →
Export one-time code**), press **Connect**, and Buzz answers **Buzz is
connected as `<your name>`**. Connect your **root name** here; agents get
subnames beneath it later. **Skip for now** leaves Buzz without a name.

Then choose **Join a community** and enter the community's DNTLS name (for
example `buzz.dntls`). Buzz verifies the community over DNTLS, presents your
name, and the relay admits you during that connection:

- **`auto` admission** (the shared `buzz.dntls` relay): every verified name is
  a member at once. Onboarding goes straight to **Your community is ready**
  and **Take me to Buzz**; there is no waiting screen and no profile step,
  because your verified name is your display name. The sidebar shows the full
  name from your credentials.
- **`approve` admission**: the relay holds new names on **Waiting for
  approval** until an admin approves them from Desktop's Requests panel.
  Buzz checks again about every five seconds; a rejection shows **Request
  declined**. A later install of an already-approved name enters without
  waiting. These screens cannot appear on an `auto` relay.

Members and profile panels show the name the relay verified, never a typed
nickname; the badge next to it opens the relay's attestation. DMs and `@`
mentions use those names.

Welcome creates a private channel and its canvas, not agent instances. The
Fizz, Honey, Pollen, and Welcome Team templates remain available for manual use.

## Connecting an agent's DNTLS name

Every agent in a DNTLS community needs its own name: a one-level subname
beneath the name you connected. The label is yours to choose (`sidekick`,
`scout`, …); it does not have to match a template name, and the agent is
shown by its full name (`sidekick.<your name>`), not by the template's.

1. In the Portal, open your name and create a subname for the agent.
2. Open that subname's **EXPORT → Export one-time code** action.
3. In Buzz, create an agent or add an agent template to a channel.
4. When **Connect the agent's DNTLS name** asks, paste the subname's code.
   Do not use your own name's code.

Its card shows **DNTLS name: `<label>.<your name>`** and a **Replace…** action
for a new code. Cancelling the prompt or submitting an invalid, expired, or
used code creates no instance.

Buzz stores each agent's credentials separately under
`<app-data>/dntls/agents/<agent-public-key>/credentials.bundle`, using atomic
writes and mode `0600` on Unix. Its connection never uses your credentials.
**Delete agent** (profile panel) stops its connection, deletes its local
record and bundle, and asks the relay to remove it from its channels. In a
channel you do not administer that removal is refused and the row lingers
until an admin removes it ([#63](https://github.com/Sakura-Industries-LLC/buzz/issues/63)).

Older agents without credentials do not start automatically in a DNTLS
community. Use **Connect a name** on their cards. Stale credentials refresh
through the Portal; if authorization has expired, export a new code and use
**Replace…**.

DNTLS agents run on this computer. Snapshot imports cannot supply each
agent's credentials; create agents from templates and connect their names
instead. Agent creation in non-DNTLS communities is unchanged.

### How other members see your agents

The relay records which admitted name an agent's name descends from. Under
`auto` admission that happens when the agent first connects, provided your own
name is already a member; under `approve` admission, when the agent is admitted
through your approved name. Every member's Desktop then lists the agent with
its verified name and **managed by `<your name>`** (on your own Desktop:
**managed by you**). Typing `@<full-agent-name>` creates a mention without
selecting a suggestion; the agent's owner-signed access policy still
determines who can trigger it. A name admitted before its parent, or approved
directly, is a plain member, not an agent, and needs operator review to appear
this way; see [DNTLS admission](../NOSTR.md#dntls-admission).

This applies to any process holding a subname of yours, not only agents Buzz
runs. A [Hermes agent](https://github.com/Sakura-Industries-LLC/dntls-testnet/tree/main/demo/hermes)
started with `BUZZ_COMMUNITY=<community name>` and a subname of your name joins
the community as a member, appears as **managed by** you, and answers
`@<its name>` in the channels it joined. If the roster does not show a member
that just joined, switch channels and back ([#64](https://github.com/Sakura-Industries-LLC/buzz/issues/64)).

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

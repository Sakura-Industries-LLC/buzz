import { expect, test } from "@playwright/test";

import { waitForAnimations } from "../helpers/animations";
import { installMockBridge } from "../helpers/bridge";
import { DNTLS_DESKTOP_COMMANDS } from "../helpers/dntls";

const OUTDIR = "test-results/add-community";
const DEFAULT_MOCK_PUBKEY = "deadbeef".repeat(8);
const COMMUNITIES = [
  {
    id: "ws-a",
    name: "Alpha",
    relayUrl: "ws://localhost:3000",
    addedAt: "2026-01-01T00:00:00.000Z",
  },
  {
    id: "ws-b",
    name: "Bravo",
    relayUrl: "ws://localhost:3001",
    addedAt: "2026-01-02T00:00:00.000Z",
  },
];

test.beforeEach(async ({ page }) => {
  await page.addInitScript((communities) => {
    window.localStorage.setItem(
      "buzz-communities",
      JSON.stringify(communities),
    );
    window.localStorage.setItem("buzz-active-community-id", communities[0].id);
  }, COMMUNITIES);
  await installMockBridge(
    page,
    {
      builderlabAuth: {
        email: "owner@example.com",
        expiresAt: "2099-01-01T00:00:00Z",
      },
      builderlabIdentity: { pubkey_hex: DEFAULT_MOCK_PUBKEY },
    },
    {
      skipCommunitySeed: true,
    },
  );
  await page.goto("/");
  await page.getByTestId("community-rail-add").click();
});

test("capture: add-community choices", async ({ page }) => {
  const dialog = page.getByTestId("add-community-dialog");
  await dialog.waitFor();
  await waitForAnimations(page);
  await dialog.screenshot({ path: `${OUTDIR}/01-choices.png` });
});

test("capture: join an existing community", async ({ page }) => {
  await page.getByTestId("add-community-join").click();
  const dialog = page.getByTestId("add-community-dialog");
  const communityUrl = page.getByLabel(
    "Community URL, DNTLS name, or invite link",
  );
  await communityUrl.fill("community.example.com");
  await page.getByTestId("community-api-token-reveal").waitFor({
    state: "detached",
  });
  await waitForAnimations(page);
  await dialog.screenshot({ path: `${OUTDIR}/02-join.png` });
});

test("joins by exact DNTLS community name", async ({ page }) => {
  await page.getByTestId("add-community-join").click();
  const communityName = page.getByLabel(
    "Community URL, DNTLS name, or invite link",
  );
  await communityName.fill("Community.Example.DNTLS.");

  const submit = page.getByTestId("invite-redeem-submit");
  await expect(submit).toBeEnabled();
  await submit.click();

  await expect
    .poll(() =>
      page.evaluate(
        (command) =>
          window.__BUZZ_E2E_COMMAND_PAYLOADS__?.some(
            (entry) =>
              entry.command === command &&
              entry.payload?.community === "community.example.dntls",
          ),
        DNTLS_DESKTOP_COMMANDS.startConnector,
      ),
    )
    .toBe(true);
  await expect
    .poll(() =>
      page.evaluate(() => window.localStorage.getItem("buzz-communities")),
    )
    .toContain('"dntlsName":"community.example.dntls"');
});

test("prompts for credentials before the first DNTLS community", async ({
  page,
}) => {
  await page.evaluate(() => {
    const config = window.__BUZZ_E2E__;
    if (!config) throw new Error("missing e2e config");
    config.mock = { ...config.mock, dntlsCredentialsName: null };
  });
  await page.getByTestId("add-community-join").click();
  await page
    .getByLabel("Community URL, DNTLS name, or invite link")
    .fill("community.example.dntls");
  await page.getByTestId("invite-redeem-submit").click();

  await expect
    .poll(() =>
      page.evaluate((commands) => {
        const payloads = window.__BUZZ_E2E_COMMAND_PAYLOADS__ ?? [];
        const importIndex = payloads.findIndex(
          (entry) => entry.command === commands.importCredentials,
        );
        const startIndex = payloads.findIndex(
          (entry) =>
            entry.command === commands.startConnector &&
            entry.payload?.community === "community.example.dntls",
        );
        return importIndex >= 0 && startIndex > importIndex;
      }, DNTLS_DESKTOP_COMMANDS),
    )
    .toBe(true);
});

test("capture: create a new community", async ({ page }) => {
  await page.getByTestId("add-community-create").click();
  const dialog = page.getByTestId("add-community-dialog");
  await page.getByLabel("Community address").waitFor();
  await waitForAnimations(page);
  await dialog.screenshot({ path: `${OUTDIR}/03-create.png` });
});

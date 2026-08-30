import { mkdirSync } from "node:fs";

import { expect, test, type Page } from "@playwright/test";

import { waitForAnimations } from "../helpers/animations";
import {
  installRelayBridge,
  openChannelBrowser,
  TEST_IDENTITIES,
} from "../helpers/bridge";
import { seedApprovedDntlsName, seedDntlsDemoMembers } from "../helpers/dntls";

const SHOTS = "test-results/dntls-badge";
const FQDN = "alice.creds";
const EXISTING_VERIFIED_FQDN = "buzzer.dntls";
const CHANNEL_NAME = "dntls-demo";
const BUZZER_PUBKEY =
  "cc77035f8d6339f839be4a96e61c2351597d1e0c7328e7f5ee67c2d4c7ea806a";

test.beforeAll(() => {
  seedDntlsDemoMembers({
    channelName: CHANNEL_NAME,
    pubkeys: [TEST_IDENTITIES.alice.pubkey, TEST_IDENTITIES.tyler.pubkey],
  });
  seedApprovedDntlsName({
    pubkey: TEST_IDENTITIES.alice.pubkey,
    fqdn: FQDN,
    approvedBy: TEST_IDENTITIES.tyler.pubkey,
  });
  mkdirSync(SHOTS, { recursive: true });
});

async function openDemoChannel(page: Page) {
  await page.getByTestId("app-sidebar").waitFor({ state: "visible" });
  const sidebarChannel = page.getByTestId(`channel-${CHANNEL_NAME}`).first();
  if (await sidebarChannel.isVisible().catch(() => false)) {
    await sidebarChannel.click();
  } else {
    await openChannelBrowser(page);
    await expect(page.getByTestId("channel-browser-dialog")).toBeVisible();
    await page.getByTestId(`browse-channel-${CHANNEL_NAME}`).first().click();
  }
  await expect(page.getByTestId("chat-title")).toHaveText(CHANNEL_NAME);
}

test("verified member messages show a DNTLS badge and proof panel", async ({
  page,
}) => {
  test.setTimeout(60_000);

  await installRelayBridge(page, "tyler");
  await page.goto("/");
  await openDemoChannel(page);

  const verifiedRow = page
    .getByTestId("message-row")
    .filter({ hasText: EXISTING_VERIFIED_FQDN })
    .first();
  await expect(verifiedRow).toBeVisible();
  await expect(verifiedRow.getByTestId("message-author")).toHaveText(
    EXISTING_VERIFIED_FQDN,
  );
  const badge = verifiedRow.getByTestId("dntls-verified-badge");
  await expect(badge).toBeVisible();
  await waitForAnimations(page);
  await page.screenshot({ path: `${SHOTS}/message-row-with-badge.png` });

  await badge.click();
  const panel = page.getByTestId("dntls-proof-panel");
  await expect(panel).toBeVisible();
  await expect(page.getByTestId("dntls-proof-identifier")).toHaveText(
    `${EXISTING_VERIFIED_FQDN}@dntls`,
  );
  await expect(panel).toContainText(
    "The relay attested that DNTLS trust-root verification bound this name to this key.",
  );
  await expect(panel).toContainText(BUZZER_PUBKEY);
  await waitForAnimations(page);
  await page.screenshot({ path: `${SHOTS}/proof-panel-open.png` });

  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();

  await expect(page.getByTestId("open-settings")).toBeVisible();
  await expect(
    page.getByTestId("open-settings").getByTestId("dntls-verified-badge"),
  ).toHaveCount(0);
  await expect(verifiedRow.getByTestId("dntls-verified-badge")).toHaveCount(1);
});

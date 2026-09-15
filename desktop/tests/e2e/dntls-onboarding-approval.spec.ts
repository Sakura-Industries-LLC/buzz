import { expect, test, type Page } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";
import { seedActiveIdentity } from "../helpers/onboarding";

const COMMUNITY_ONBOARDING_TRANSACTION_STORAGE_KEY =
  "buzz-community-onboarding-transaction.v1";
const DNTLS_COMMUNITY = "community.example.dntls";
const PENDING_AUTH = "restricted: dntls approval pending";
const PENDING_HTTP = "relay returned 403 Forbidden: dntls_approval_pending";
const DENIED_AUTH = "restricted: not a relay member";
const AUTO_ENTER_TIMEOUT_MS = 25_000;
const BLANK_TYLER_IDENTITY = {
  ...TEST_IDENTITIES.tyler,
  username: "",
};

type MockPatch = {
  profileReadError?: string | null;
  profileUpdateError?: string | null;
  profileUpdateErrors?: string[];
  profileHasEvent?: boolean;
};

type E2eWindow = Window & {
  __BUZZ_E2E__?: { mock?: Record<string, unknown> };
  __BUZZ_E2E_QUEUE_AUTH_RESPONSES__?: (
    responses: Array<{ success: boolean; message: string }>,
  ) => void;
};

async function bootFirstCommunity(page: Page, mock?: MockPatch) {
  await seedActiveIdentity(page, BLANK_TYLER_IDENTITY);
  await page.addInitScript((pubkey) => {
    window.localStorage.setItem(
      `buzz-machine-onboarding-complete.v2:${pubkey}`,
      "true",
    );
  }, BLANK_TYLER_IDENTITY.pubkey);
  await installMockBridge(
    page,
    {
      profileHasEvent: false,
      ...mock,
    },
    {
      relayWsUrl: "ws://localhost:3000",
      skipOnboardingSeed: true,
      skipCommunitySeed: true,
    },
  );
  await page.goto("/");
  await expect(page.getByTestId("welcome-setup")).toBeVisible();
}

async function joinFirstDntlsCommunity(page: Page) {
  await page.getByRole("button", { name: /Join a community/ }).click();
  await page.getByTestId("invite-redeem-input").fill(DNTLS_COMMUNITY);
  await page.getByTestId("invite-redeem-submit").click();
}

async function queueAuthResponses(
  page: Page,
  responses: Array<{ success: boolean; message: string }>,
) {
  await page.waitForFunction(
    () =>
      typeof (window as E2eWindow).__BUZZ_E2E_QUEUE_AUTH_RESPONSES__ ===
      "function",
  );
  await page.evaluate((queued) => {
    const queue = (window as E2eWindow).__BUZZ_E2E_QUEUE_AUTH_RESPONSES__;
    if (!queue) throw new Error("E2E AUTH response seam is not installed.");
    queue(queued);
  }, responses);
}

async function patchMock(page: Page, patch: MockPatch) {
  await page.evaluate((next) => {
    const config = (window as E2eWindow).__BUZZ_E2E__;
    if (!config) throw new Error("missing e2e config");
    const mock = { ...(config.mock ?? {}) };
    for (const [key, value] of Object.entries(next)) {
      if (value === null) {
        delete mock[key];
      } else {
        mock[key] = value;
      }
    }
    config.mock = mock;
  }, patch);
}

async function readOnboardingTransaction(page: Page) {
  return page.evaluate((storageKey) => {
    const raw = window.localStorage.getItem(storageKey);
    return raw ? (JSON.parse(raw) as { stage?: string; error?: string }) : null;
  }, COMMUNITY_ONBOARDING_TRANSACTION_STORAGE_KEY);
}

async function expectAwaitingApprovalWithoutProfile(
  page: Page,
  options?: { stage?: "connecting" },
) {
  await expect(page.getByTestId("awaiting-approval")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Waiting for approval" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Build your profile" }),
  ).toHaveCount(0);
  await expect(page.getByTestId("community-profile-name-key")).toHaveCount(0);
  if (options?.stage) {
    await expect
      .poll(async () => (await readOnboardingTransaction(page))?.stage ?? null)
      .toBe(options.stage);
  }
}

async function expectMembershipDeniedWithoutProfile(page: Page) {
  await expect(page.getByTestId("membership-denied")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Request declined" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Not a member yet" }),
  ).toHaveCount(0);
  await expect(page.getByText("Your public key (npub)")).toHaveCount(0);
  await expect(page.getByTestId("membership-denied-redeem-invite")).toHaveCount(
    0,
  );
  await expect(page.getByTestId("membership-denied-change-key")).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Build your profile" }),
  ).toHaveCount(0);
  await expect(page.getByTestId("community-profile-name-key")).toHaveCount(0);
}

async function expectAutoEntered(page: Page) {
  await expect(page.getByTestId("awaiting-approval")).toHaveCount(0, {
    timeout: AUTO_ENTER_TIMEOUT_MS,
  });
  await expect(page.getByTestId("membership-denied")).toHaveCount(0);
  await expect(page.getByTestId("community-profile-name-key")).toHaveCount(0);
  await expect(
    page.getByTestId("home-inbox-list").or(page.getByTestId("chat-title")),
  ).toBeVisible({ timeout: AUTO_ENTER_TIMEOUT_MS });
  await expect.poll(() => readOnboardingTransaction(page)).toBeNull();
}

test("first DNTLS join AUTH pending waits then auto-enters after approval", async ({
  page,
}) => {
  test.setTimeout(45_000);
  await bootFirstCommunity(page);
  await queueAuthResponses(
    page,
    Array.from({ length: 3 }, () => ({
      success: false,
      message: PENDING_AUTH,
    })),
  );
  await joinFirstDntlsCommunity(page);

  await expectAwaitingApprovalWithoutProfile(page, { stage: "connecting" });
  await expect
    .poll(async () => (await readOnboardingTransaction(page))?.error ?? "")
    .toContain(PENDING_AUTH);

  await queueAuthResponses(
    page,
    Array.from({ length: 4 }, () => ({ success: true, message: "" })),
  );
  await expectAutoEntered(page);
});

for (const [name, mock, clear] of [
  ["lookup", { profileReadError: PENDING_HTTP }, { profileReadError: null }],
  [
    "publish",
    { profileUpdateErrors: Array.from({ length: 10 }, () => PENDING_HTTP) },
    { profileUpdateErrors: [] },
  ],
] as const) {
  test(`first DNTLS join HTTP profile ${name} pending waits then auto-enters after approval`, async ({
    page,
  }) => {
    test.setTimeout(45_000);
    await bootFirstCommunity(page, mock);
    await joinFirstDntlsCommunity(page);

    await expectAwaitingApprovalWithoutProfile(
      page,
      name === "lookup" ? { stage: "connecting" } : undefined,
    );
    if (name === "lookup") {
      await expect
        .poll(async () => (await readOnboardingTransaction(page))?.error ?? "")
        .toContain(PENDING_HTTP);
    }

    await patchMock(page, clear);
    await expectAutoEntered(page);
  });
}

test("pending first DNTLS join rejection shows declined request without profile", async ({
  page,
}) => {
  await bootFirstCommunity(page);
  await queueAuthResponses(page, [{ success: false, message: PENDING_AUTH }]);
  await joinFirstDntlsCommunity(page);
  await expectAwaitingApprovalWithoutProfile(page, { stage: "connecting" });
  await queueAuthResponses(
    page,
    Array.from({ length: 10 }, () => ({
      success: false,
      message: DENIED_AUTH,
    })),
  );

  await expectMembershipDeniedWithoutProfile(page);
  await expect
    .poll(async () => (await readOnboardingTransaction(page))?.stage ?? null)
    .toBe("connecting");
});

test("approved DNTLS reinstall needs no further membership approval", async ({
  page,
}) => {
  test.setTimeout(45_000);
  await bootFirstCommunity(page);
  await joinFirstDntlsCommunity(page);
  await expect(
    page.getByRole("button", { name: "Take me to Buzz" }),
  ).toBeVisible();
  await expect(page.getByTestId("awaiting-approval")).toHaveCount(0);
  await expect(page.getByTestId("membership-denied")).toHaveCount(0);
  await page.getByRole("button", { name: "Take me to Buzz" }).click();
  await expectAutoEntered(page);
});

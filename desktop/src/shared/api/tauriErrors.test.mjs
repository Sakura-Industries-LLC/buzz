import assert from "node:assert/strict";
import test from "node:test";
import {
  captureTauriErrorObservers,
  subscribeToTauriErrors,
  toTauriError,
} from "./tauriErrors.ts";
import { membershipGateViewForError } from "../../features/onboarding/membershipGate.ts";

test("native admission errors retain their gate after normalization", () => {
  for (const payload of [
    "relay returned 403 Forbidden: dntls_approval_pending",
    { message: "relay returned 403 Forbidden: dntls_approval_pending" },
  ]) {
    assert.equal(
      membershipGateViewForError(toTauriError(payload)),
      "awaiting-approval",
    );
  }
});

test("late failures do not gate a replacement onboarding flow", () => {
  const first = [];
  const replacement = [];
  const unsubscribeFirst = subscribeToTauriErrors((error) => first.push(error));
  const notifyOldRequest = captureTauriErrorObservers();
  unsubscribeFirst();
  const unsubscribeReplacement = subscribeToTauriErrors((error) =>
    replacement.push(error),
  );
  try {
    const pending = toTauriError(
      "relay returned 403 Forbidden: dntls_approval_pending",
    );
    notifyOldRequest(pending);
    assert.deepEqual(first, []);
    assert.deepEqual(replacement, []);
    captureTauriErrorObservers()(pending);
    assert.equal(
      membershipGateViewForError(replacement[0]),
      "awaiting-approval",
    );
  } finally {
    unsubscribeFirst();
    unsubscribeReplacement();
  }
});

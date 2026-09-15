import assert from "node:assert/strict";
import test from "node:test";

import {
  membershipGateViewForError,
  isDntlsApprovalPendingError,
  isRelayMembershipDeniedError,
} from "./membershipGate.ts";

test("pending AUTH and HTTP codes route to awaiting-approval", () => {
  for (const message of [
    "restricted: dntls approval pending",
    "relay returned 403: dntls_approval_pending",
    "Relay returned 403: Restricted: DNTLS approval pending",
  ]) {
    const error = new Error(message);
    assert.equal(membershipGateViewForError(error), "awaiting-approval");
    assert.equal(isDntlsApprovalPendingError(error), true);
    assert.equal(
      isRelayMembershipDeniedError(error),
      false,
      "pending must not look like a terminal membership denial",
    );
  }
});

test("ordinary membership denial is terminal", () => {
  for (const message of [
    "restricted: not a relay member",
    "invalid: you are not a relay member",
    "You must be a relay member",
    "relay_membership_required",
    "relay returned 403: restricted: not a relay member",
  ]) {
    const error = new Error(message);
    assert.equal(membershipGateViewForError(error), "membership-denied");
    assert.equal(isRelayMembershipDeniedError(error), true);
  }
});

test("pending then generic denial switches the gate to MembershipDenied", () => {
  assert.equal(
    membershipGateViewForError(new Error("restricted: dntls approval pending")),
    "awaiting-approval",
  );
  assert.equal(
    membershipGateViewForError(new Error("restricted: not a relay member")),
    "membership-denied",
  );
});

test("unrelated errors do not open a membership gate", () => {
  assert.equal(membershipGateViewForError(new Error("relay unreachable")), null);
  assert.equal(membershipGateViewForError("restricted: not a relay member"), null);
});

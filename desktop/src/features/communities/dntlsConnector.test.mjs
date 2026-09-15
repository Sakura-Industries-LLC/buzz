import assert from "node:assert/strict";
import test from "node:test";

import {
  dntlsCommunityName,
  isCredentialsChangedError,
  isDntlsError,
  needsCredentialsImport,
} from "./dntlsConnector.ts";

test("normalizes exact DNTLS community names", () => {
  assert.equal(
    dntlsCommunityName("Relay.Example.DNTLS."),
    "relay.example.dntls",
  );
  for (const value of [
    "dntls",
    ".dntls",
    "https://relay.example.dntls",
    "-relay.example.dntls",
  ]) {
    assert.equal(dntlsCommunityName(value), null, value);
  }
});

test("prompts for credentials only when none are stored", () => {
  assert.equal(needsCredentialsImport({ name: null }), true);
  assert.equal(needsCredentialsImport({ name: "" }), true);
  assert.equal(needsCredentialsImport({ name: "demo-alice.dntls" }), false);
});

test("recognizes structured DNTLS errors by code and message", () => {
  assert.equal(
    isDntlsError({ code: "denied", message: "the user declined" }),
    true,
  );
  assert.equal(isDntlsError({ code: "denied" }), false);
  assert.equal(isDntlsError({ message: "the user declined" }), false);
  assert.equal(isDntlsError(new Error("denied")), false);
  assert.equal(isDntlsError("denied"), false);
});

test("detects credential rotation from code or backend plain text", () => {
  const message =
    "Your name's credentials changed. Export a new one-time code.";
  assert.equal(
    isCredentialsChangedError({ code: "credentials_changed", message }),
    true,
  );
  assert.equal(
    isCredentialsChangedError({ code: "unavailable", message }),
    true,
  );
  assert.equal(isCredentialsChangedError(new Error(message)), true);
  assert.equal(isCredentialsChangedError(message), true);
  assert.equal(
    isCredentialsChangedError({
      code: "unavailable",
      message: "Couldn't reach the DNTLS Portal. Try again.",
    }),
    false,
  );
});

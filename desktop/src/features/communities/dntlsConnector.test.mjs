import assert from "node:assert/strict";
import test from "node:test";

import {
  dntlsCommunityName,
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

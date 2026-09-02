import assert from "node:assert/strict";
import test from "node:test";

import { dntlsCommunityName } from "./dntlsConnector.ts";

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

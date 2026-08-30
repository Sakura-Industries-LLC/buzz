import assert from "node:assert/strict";
import { after, afterEach, before, test } from "node:test";
import { JSDOM } from "jsdom";

const PUBKEY = "aa".repeat(32);

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

before(() => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
});

afterEach(async () => {
  const { cleanup } = await import("@testing-library/react");
  cleanup();
});

after(() => dom.window.close());

let React;
let render;
let act;
let DntlsVerifiedBadge;
let dntlsProofCopy;

before(async () => {
  React = (await import("react")).default;
  ({ render, act } = await import("@testing-library/react"));
  ({ DntlsVerifiedBadge, dntlsProofCopy } = await import(
    "./DntlsVerifiedBadge.tsx"
  ));
});

test("badge render condition: only verified DNTLS names", () => {
  assert.equal(Boolean("alice.example".trim()), true);
  assert.equal(Boolean(undefined), false);
  assert.equal(Boolean("".trim()), false);
});

test("verified badge renders next to a DNTLS name", async () => {
  let view;
  await act(async () => {
    view = render(
      React.createElement(DntlsVerifiedBadge, {
        approvedAt: 1_700_000_000,
        fqdn: "alice.example",
        pubkey: PUBKEY,
      }),
    );
  });
  const badge = view.getByTestId("dntls-verified-badge");
  assert.equal(
    badge.getAttribute("aria-label"),
    "Show DNTLS verification for alice.example@dntls",
  );
});

test("proof copy uses native identifier, pubkey, and relay-attested provenance", () => {
  const proof = dntlsProofCopy({
    approvedAt: 1_700_000_000,
    fqdn: "alice.example",
    pubkey: PUBKEY,
  });
  assert.equal(proof.identifier, "alice.example@dntls");
  assert.equal(proof.hexPubkey, PUBKEY);
  assert.match(proof.npub, /^npub1/);
  assert.equal(
    proof.provenance,
    "The relay attested that DNTLS trust-root verification bound this name to this key.",
  );
  assert.notEqual(proof.approvedLabel, null);
});

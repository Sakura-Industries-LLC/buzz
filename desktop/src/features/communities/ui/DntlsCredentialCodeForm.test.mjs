import assert from "node:assert/strict";
import { after, afterEach, before, test } from "node:test";

import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

let redeemResult = { name: "alice.dntls" };
let redeemError = null;

function installInvoke() {
  const invoke = async (command, args = {}) => {
    if (command !== "redeem_dntls_credential_code") {
      throw new Error(`unexpected command ${command}`);
    }
    if (redeemError) throw redeemError;
    return redeemResult;
  };
  dom.window.__TAURI_INTERNALS__ = { invoke };
  globalThis.__TAURI_INTERNALS__ = { invoke };
}

before(() => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
  installInvoke();
});

afterEach(async () => {
  redeemResult = { name: "alice.dntls" };
  redeemError = null;
  const { cleanup } = await import("@testing-library/react");
  cleanup();
});

after(() => dom.window.close());

async function renderForm(props = {}) {
  const React = await import("react");
  const { render } = await import("@testing-library/react");
  const { DntlsCredentialCodeForm } = await import(
    "./DntlsCredentialCodeForm.tsx"
  );
  const onConnected = props.onConnected ?? (() => {});
  return render(
    React.createElement(DntlsCredentialCodeForm, { onConnected, ...props }),
  );
}

test("a rejected code stays retryable and clears its error after success", async () => {
  redeemError = {
    code: "credential_code_invalid",
    message: "ignored backend wording",
  };
  const { fireEvent, screen } = await import("@testing-library/react");
  await renderForm();
  fireEvent.change(screen.getByTestId("dntls-credential-code-input"), {
    target: { value: "used-code" },
  });
  fireEvent.click(screen.getByTestId("dntls-credential-code-connect"));
  await screen.findByTestId("dntls-credential-code-error");
  assert.equal(
    screen.getByTestId("dntls-credential-code-connect").disabled,
    false,
  );
  assert.equal(screen.queryByTestId("dntls-credential-code-bound"), null);
  redeemError = null;
  fireEvent.click(screen.getByTestId("dntls-credential-code-connect"));
  await screen.findByTestId("dntls-credential-code-bound");
  assert.equal(screen.queryByTestId("dntls-credential-code-error"), null);
});

test("displays the redeemed FQDN as-is", async () => {
  redeemResult = { name: "buzz.demo-alice.dntls" };
  const connected = [];
  const { fireEvent, screen } = await import("@testing-library/react");
  await renderForm({ onConnected: (name) => connected.push(name) });
  fireEvent.change(screen.getByTestId("dntls-credential-code-input"), {
    target: { value: "AAAA-BBBB-CCCC" },
  });
  fireEvent.click(screen.getByTestId("dntls-credential-code-connect"));
  const bound = await screen.findByTestId("dntls-credential-code-bound");
  assert.match(
    bound.textContent,
    /Buzz is connected as buzz\.demo-alice\.dntls/,
  );
  fireEvent.click(screen.getByTestId("dntls-credential-code-continue"));
  assert.deepEqual(connected, ["buzz.demo-alice.dntls"]);
});

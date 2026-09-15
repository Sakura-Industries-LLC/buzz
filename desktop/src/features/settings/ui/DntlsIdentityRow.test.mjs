import assert from "node:assert/strict";
import { after, afterEach, before, test } from "node:test";

import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

let storedName = "alice.dntls";
const removed = [];

function installInvoke() {
  const invoke = async (command) => {
    if (command === "dntls_credentials_status") {
      return { name: storedName };
    }
    if (command === "remove_dntls_credentials") {
      removed.push(storedName);
      storedName = null;
      return null;
    }
    throw new Error(`unexpected command ${command}`);
  };
  dom.window.__TAURI_INTERNALS__ = { invoke };
  globalThis.__TAURI_INTERNALS__ = { invoke };
}

before(() => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    HTMLInputElement: dom.window.HTMLInputElement,
    Node: dom.window.Node,
    NodeFilter: dom.window.NodeFilter,
    MutationObserver: dom.window.MutationObserver,
    CustomEvent: dom.window.CustomEvent,
    getComputedStyle: dom.window.getComputedStyle.bind(dom.window),
    localStorage: dom.window.localStorage,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
  dom.window.matchMedia = () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  });
  installInvoke();
});

afterEach(async () => {
  storedName = "alice.dntls";
  removed.length = 0;
  const { cleanup } = await import("@testing-library/react");
  cleanup();
});

after(() => dom.window.close());

async function renderRow() {
  const React = await import("react");
  const { act, render } = await import("@testing-library/react");
  const { DntlsIdentityRow } = await import("./DntlsIdentityRow.tsx");
  const { ThemeProvider } = await import("@/shared/theme/ThemeProvider.tsx");
  let view;
  await act(async () => {
    view = render(
      React.createElement(
        ThemeProvider,
        null,
        React.createElement(DntlsIdentityRow),
      ),
    );
  });
  return view;
}

test("replace opens the shared one-time code form", async () => {
  const { fireEvent, screen } = await import("@testing-library/react");
  await renderRow();
  await screen.findByText("DNTLS identity: alice.dntls");
  fireEvent.click(screen.getByTestId("profile-dntls-identity-replace"));
  assert.ok(screen.getByTestId("dntls-credential-code-form"));
  assert.ok(screen.getByTestId("dntls-credential-code-input"));
});

test("remove clears the connected name", async () => {
  const { fireEvent, screen } = await import("@testing-library/react");
  await renderRow();
  await screen.findByText("DNTLS identity: alice.dntls");
  await fireEvent.click(screen.getByTestId("profile-dntls-identity-remove"));
  await screen.findByText("DNTLS identity: not set");
  assert.deepEqual(removed, ["alice.dntls"]);
  assert.equal(screen.queryByTestId("profile-dntls-identity-remove"), null);
});

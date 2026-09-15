import assert from "node:assert/strict";
import { after, test } from "node:test";
import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
Object.assign(globalThis, {
  document: dom.window.document,
  window: dom.window,
  localStorage: dom.window.localStorage,
  HTMLElement: dom.window.HTMLElement,
  IS_REACT_ACT_ENVIRONMENT: true,
});
after(() => dom.window.close());

test("a late startup response cannot overwrite a credential-replacement reconnect", async () => {
  const pending = [];
  const invoke = (command) => {
    assert.equal(command, "start_dntls_connector");
    return new Promise((resolve) => pending.push(resolve));
  };
  dom.window.__TAURI_INTERNALS__ = { invoke };
  globalThis.__TAURI_INTERNALS__ = { invoke };
  localStorage.setItem(
    "buzz-communities",
    JSON.stringify([
      {
        id: "community",
        name: "Buzz",
        dntlsName: "buzz.dntls",
        relayUrl: "ws://127.0.0.1:1000",
      },
    ]),
  );
  localStorage.setItem("buzz-active-community-id", "community");
  const React = await import("react");
  const { act, renderHook, cleanup } = await import("@testing-library/react");
  const { CommunitiesProvider, useCommunities } = await import(
    "./useCommunities.tsx"
  );
  const { result } = renderHook(useCommunities, {
    wrapper: ({ children }) =>
      React.createElement(CommunitiesProvider, null, children),
  });
  let retry;
  act(() => {
    retry = result.current.retryDntlsConnectors();
  });
  await act(async () => {
    pending[1]({ community: "buzz.dntls", relay_url: "ws://127.0.0.1:2000" });
    await retry;
  });
  await act(async () => {
    pending[0]({ community: "buzz.dntls", relay_url: "ws://127.0.0.1:1001" });
  });
  assert.equal(result.current.activeCommunity.relayUrl, "ws://127.0.0.1:2000");
  assert.equal(
    JSON.parse(localStorage.getItem("buzz-communities"))[0].relayUrl,
    "ws://127.0.0.1:2000",
  );
  cleanup();
});

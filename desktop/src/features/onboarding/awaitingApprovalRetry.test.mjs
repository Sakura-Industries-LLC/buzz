import assert from "node:assert/strict";
import test from "node:test";

import { startAwaitingApprovalRetry } from "./awaitingApprovalRetry.ts";

test("stop cancels a scheduled retry so a community switch cannot resume", async () => {
  const timers = [];
  const schedule = (fn) => {
    const id = timers.length;
    timers.push(fn);
    return id;
  };
  const unschedule = (id) => {
    timers[id] = null;
  };
  let attempts = 0;
  let continued = 0;
  let denied = 0;
  const stop = startAwaitingApprovalRetry({
    attempt: async () => {
      attempts += 1;
      return "pending";
    },
    onContinue: () => {
      continued += 1;
    },
    onDenied: () => {
      denied += 1;
    },
    delayMs: 5_000,
    schedule,
    unschedule,
  });

  assert.equal(attempts, 0, "first retry waits the cadence");
  assert.equal(typeof timers[0], "function");
  stop();
  timers[0]?.();
  await Promise.resolve();
  assert.equal(attempts, 0);
  assert.equal(continued, 0);
  assert.equal(denied, 0);
});

test("a later generic denial reports denied instead of continuing to wait", async () => {
  const timers = [];
  const schedule = (fn) => {
    timers.push(fn);
    return timers.length - 1;
  };
  let results = ["pending", "denied"];
  let denied = 0;
  let continued = 0;
  startAwaitingApprovalRetry({
    attempt: async () => results.shift() ?? "pending",
    onContinue: () => {
      continued += 1;
    },
    onDenied: () => {
      denied += 1;
    },
    delayMs: 5_000,
    schedule,
    unschedule: () => {},
  });

  await timers[0]();
  await Promise.resolve();
  assert.equal(denied, 0);
  await timers[1]();
  await Promise.resolve();
  assert.equal(denied, 1);
  assert.equal(continued, 0);
});

test("successful AUTH stops waiting and continues", async () => {
  const timers = [];
  const schedule = (fn) => {
    timers.push(fn);
    return timers.length - 1;
  };
  let continued = 0;
  startAwaitingApprovalRetry({
    attempt: async () => "continue",
    onContinue: () => {
      continued += 1;
    },
    onDenied: () => {},
    delayMs: 5_000,
    schedule,
    unschedule: () => {},
  });

  await timers[0]();
  await Promise.resolve();
  assert.equal(continued, 1);
});

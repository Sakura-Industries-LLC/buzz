import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import {
  cancelAgentCodeRequests,
  currentAgentCodeRequest,
  withAgentDntlsCode,
} from "./agentDntlsCode.ts";

afterEach(cancelAgentCodeRequests);

test("cancelling the code step never calls agent creation", async () => {
  let created = false;
  const result = withAgentDntlsCode("buzz.dntls", async () => {
    created = true;
  });
  const rejected = assert.rejects(result, /cancelled/);
  currentAgentCodeRequest().cancel();
  await rejected;
  assert.equal(created, false);
  assert.equal(currentAgentCodeRequest(), null);
});

test("a rejected code leaves creation pending and retryable", async () => {
  const created = [];
  const result = withAgentDntlsCode("buzz.dntls", async (code) => {
    if (code === "used-code") throw new Error("Export a new one-time code.");
    created.push("fizz.alice.dntls");
    return { name: "fizz.alice.dntls" };
  });
  const request = currentAgentCodeRequest();
  await assert.rejects(request.submit("used-code"), /new one-time code/);
  assert.deepEqual(created, []);
  assert.equal(currentAgentCodeRequest(), request);
  await request.submit("fresh-code");
  assert.deepEqual(await result, { name: "fizz.alice.dntls" });
  assert.deepEqual(created, ["fizz.alice.dntls"]);
  assert.equal(currentAgentCodeRequest(), null);
});

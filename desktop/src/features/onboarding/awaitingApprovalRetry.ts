import { PENDING_AUTH_RETRY_MS } from "@/shared/api/relayAuthPolicy";

export type ApprovalRetryResult = "continue" | "denied" | "pending";

/**
 * Retry `attempt` on a fixed cadence until it reports continue/denied or
 * `stop` runs. Community switch and unmount must call the returned stopper
 * so a stale attempt cannot resume the previous community's wait.
 *
 * The first retry waits `delayMs` — the triggering pending error already
 * happened. `onContinue` / `onDenied` are skipped after stop.
 */
export function startAwaitingApprovalRetry(options: {
  attempt: () => Promise<ApprovalRetryResult>;
  onContinue: () => void;
  onDenied: () => void;
  delayMs?: number;
  schedule?: (fn: () => void, ms: number) => unknown;
  unschedule?: (id: unknown) => void;
}): () => void {
  const delayMs = options.delayMs ?? PENDING_AUTH_RETRY_MS;
  const schedule = options.schedule ?? setTimeout;
  const unschedule =
    options.unschedule ?? ((id: unknown) => clearTimeout(id as number));
  let stopped = false;
  let timer: unknown = null;

  const arm = () => {
    if (stopped) return;
    timer = schedule(() => {
      timer = null;
      if (stopped) return;
      void options.attempt().then((result) => {
        if (stopped) return;
        if (result === "continue") {
          options.onContinue();
          return;
        }
        if (result === "denied") {
          options.onDenied();
          return;
        }
        arm();
      });
    }, delayMs);
  };

  arm();

  return () => {
    stopped = true;
    if (timer !== null) {
      unschedule(timer);
      timer = null;
    }
  };
}

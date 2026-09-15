/**
 * Policy for NIP-42 AUTH `OK` responses (G2 of the CMD+R gap audit).
 *
 * Historically ANY auth `OK false` latched the session terminal — no
 * reconnect until explicit user re-engagement. But the relay sends
 * `OK false` for conditions that are transient from the client's side:
 *
 *  - `auth-required: already authenticated` — a duplicate/late AUTH event on
 *    a connection that is in fact authenticated. The session is usable;
 *    treat it as authenticated.
 *  - `auth-required: verification failed` — covers ±60s clock-skew rejects
 *    and the relay's fail-closed allowlist DB lookup errors, both of which
 *    can clear on retry.
 *  - `restricted: dntls approval pending` — the identity is queued for
 *    owner/admin admission. Retry on a fresh connection at a fixed ~5s
 *    cadence so the relay sees the DNTLS name again. This reason is not
 *    terminal and must not count toward `MAX_CONSECUTIVE_AUTH_REJECTIONS`.
 *
 * Other `restricted:` and `blocked:` rejections (not a relay member / banned)
 * are known permanent. Everything else retries with normal backoff, but
 * latches terminal after `MAX_CONSECUTIVE_AUTH_REJECTIONS` consecutive
 * rejections so a genuinely broken identity (e.g. persistently wrong system
 * clock) still surfaces the terminal error card instead of flapping forever.
 *
 * The rejection streak is preserved across environment-driven resume
 * attempts (focus/online/visibility); only explicit user re-engagement —
 * the reconnect card or a community switch — may reset it. Pending
 * approval does not increment or reset the streak.
 *
 * After a pending phase, a persisted rejection answers
 * `restricted: not a relay member` and is terminal MembershipDenied.
 */
export type AuthOkDecision = "authenticated" | "retry" | "terminal";

export const MAX_CONSECUTIVE_AUTH_REJECTIONS = 3;

/** Exact AUTH `OK false` reason the relay sends for a queued DNTLS applicant. */
export const DNTLS_APPROVAL_PENDING_REASON =
  "restricted: dntls approval pending";

/** HTTP 403 error code for the same pending admission gate (NIP-98). */
export const DNTLS_APPROVAL_PENDING_CODE = "dntls_approval_pending";

/** Fixed reconnect cadence while AUTH is waiting on DNTLS approval. */
export const PENDING_AUTH_RETRY_MS = 5_000;

export type RelayAuthRequest = {
  pendingEventId: string;
  resolve: () => void;
  reject: (error: Error) => void;
  timeout: number;
};

export function armRelayAuthentication(
  timeoutMs: number,
  setRequest: (request: RelayAuthRequest) => void,
  onTimeout: (error: Error) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      const error = new Error("Relay authentication timed out.");
      onTimeout(error);
      reject(error);
    }, timeoutMs);
    setRequest({ pendingEventId: "", resolve, reject, timeout });
  });
}

/** True when an AUTH/HTTP error string is the DNTLS pending-admission signal. */
export function isDntlsApprovalPendingReason(message: string): boolean {
  const normalized = message.trim().toLowerCase();
  return (
    normalized.includes(DNTLS_APPROVAL_PENDING_REASON) ||
    normalized.includes(DNTLS_APPROVAL_PENDING_CODE)
  );
}

/**
 * Fixed delay for a pending-approval AUTH retry, or `undefined` to keep the
 * session's exponential backoff.
 */
export function authReconnectDelayMs(message: string): number | undefined {
  return isDntlsApprovalPendingReason(message)
    ? PENDING_AUTH_RETRY_MS
    : undefined;
}

/** Tracks consecutive AUTH rejections across reconnect attempts. */
export class AuthOkTracker {
  private consecutiveRejections = 0;

  /**
   * Record an AUTH `OK` and decide the session's next move.
   * A success — real or "already authenticated" — resets the streak.
   * Pending DNTLS approval retries without touching the streak.
   */
  record(success: boolean, message: string): AuthOkDecision {
    const normalized = message.trim().toLowerCase();
    if (
      success ||
      normalized.startsWith("auth-required: already authenticated")
    ) {
      this.consecutiveRejections = 0;
      return "authenticated";
    }

    if (isDntlsApprovalPendingReason(normalized)) {
      return "retry";
    }

    this.consecutiveRejections++;

    if (
      normalized.startsWith("restricted:") ||
      normalized.startsWith("blocked:")
    ) {
      return "terminal";
    }
    if (this.consecutiveRejections >= MAX_CONSECUTIVE_AUTH_REJECTIONS) {
      return "terminal";
    }
    return "retry";
  }

  /** Called on explicit re-engagement (disconnect / manual preconnect). */
  reset(): void {
    this.consecutiveRejections = 0;
  }
}

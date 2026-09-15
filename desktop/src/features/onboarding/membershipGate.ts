import { isDntlsApprovalPendingReason } from "@/shared/api/relayAuthPolicy";

/**
 * Classify errors from AUTH, NIP-98 HTTP, and profile publish so both
 * onboarding flows route pending applicants to AwaitingApproval and
 * ordinary membership denial to MembershipDenied.
 *
 * A persisted rejection for the same pubkey answers
 * `restricted: not a relay member`. Pending → that generic denial must
 * switch AwaitingApproval to MembershipDenied. A different pubkey may
 * queue a new pending row for the same name.
 */
export type MembershipGateView = "awaiting-approval" | "membership-denied";

export function isDntlsApprovalPendingError(error: unknown): boolean {
  return error instanceof Error && isDntlsApprovalPendingReason(error.message);
}

export function isRelayMembershipDeniedError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (isDntlsApprovalPendingError(error)) return false;
  return (
    error.message.includes("You must be a relay member") ||
    error.message.includes("relay_membership_required") ||
    error.message.includes("restricted: not a relay member") ||
    error.message.includes("invalid: you are not a relay member")
  );
}

export function membershipGateViewForError(
  error: unknown,
): MembershipGateView | null {
  if (isDntlsApprovalPendingError(error)) return "awaiting-approval";
  if (isRelayMembershipDeniedError(error)) return "membership-denied";
  return null;
}

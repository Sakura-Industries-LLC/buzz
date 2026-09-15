import type {
  DntlsNamesMap,
  DntlsPendingApplication,
  ListPendingDntlsApplicationsResult,
} from "@/shared/api/dntls";
import { normalizePubkey } from "@/shared/lib/pubkey";

export const DNTLS_PENDING_REFETCH_INTERVAL_MS = 5_000;

export const dntlsPendingApplicationsQueryKey = (relayUrl: string) =>
  ["dntls-pending", relayUrl] as const;

export function canShowDntlsRequestsSection(input: {
  role: string | null | undefined;
  isSuccess: boolean;
  result: ListPendingDntlsApplicationsResult | undefined;
}): boolean {
  if (input.role !== "owner" && input.role !== "admin") {
    return false;
  }
  if (!input.isSuccess || input.result?.status !== "ok") {
    return false;
  }
  return input.result.applications.length > 0;
}

export function dntlsRequestJoinCopy(name: string): string {
  return `${name} wants to join`;
}

export function formatDntlsRequestedAt(
  createdAtSeconds: number,
  nowMs = Date.now(),
): string {
  const createdMs = createdAtSeconds * 1000;
  const diffMs = Math.max(0, nowMs - createdMs);
  const diffMins = Math.floor(diffMs / 60_000);
  if (diffMins < 1) return "requested just now";
  if (diffMins < 60) return `requested ${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `requested ${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `requested ${diffDays}d ago`;
  return `requested ${new Date(createdMs).toLocaleDateString()}`;
}

export function removePendingDntlsApplication(
  current: ListPendingDntlsApplicationsResult | undefined,
  pubkey: string,
): ListPendingDntlsApplicationsResult | undefined {
  if (!current || current.status !== "ok") {
    return current;
  }
  const needle = normalizePubkey(pubkey);
  return {
    status: "ok",
    applications: current.applications.filter(
      (application) => normalizePubkey(application.pubkey) !== needle,
    ),
  };
}

export function seedApprovedDntlsName(
  current: DntlsNamesMap | undefined,
  application: Pick<DntlsPendingApplication, "pubkey" | "fqdn">,
  approvedAtSeconds: number,
): DntlsNamesMap {
  const next = new Map(current ?? []);
  const pubkey = normalizePubkey(application.pubkey);
  if (!pubkey || !application.fqdn.trim()) {
    return next;
  }
  next.set(pubkey, {
    fqdn: application.fqdn.trim(),
    approvedAt: approvedAtSeconds,
  });
  return next;
}

export function beginDntlsRequestAction(
  inFlight: Set<string>,
  pubkey: string,
): boolean {
  const key = normalizePubkey(pubkey);
  if (!key || inFlight.has(key)) {
    return false;
  }
  inFlight.add(key);
  return true;
}

export function endDntlsRequestAction(inFlight: Set<string>, pubkey: string) {
  inFlight.delete(normalizePubkey(pubkey));
}

export function relayMemberDisplayName(
  member: { role: string },
  profile?: {
    displayName?: string | null;
    verifiedDntlsName?: string | null;
  } | null,
): string {
  const verified = profile?.verifiedDntlsName?.trim();
  if (verified) {
    return verified;
  }
  const trimmedDisplayName = profile?.displayName?.trim();
  if (
    trimmedDisplayName &&
    !trimmedDisplayName.toLowerCase().startsWith("npub1")
  ) {
    return trimmedDisplayName;
  }
  return member.role === "owner" ? "Community owner" : "Unnamed member";
}

import { useQuery } from "@tanstack/react-query";

import { useCommunities } from "@/features/communities/useCommunities";
import { fetchDntlsNames, type DntlsNamesMap } from "@/shared/api/dntls";
import { useFocusedRefetchInterval } from "@/shared/lib/useDocumentVisible";

const DNTLS_NAMES_REFETCH_INTERVAL_MS = 60_000;

export const dntlsNamesQueryKey = (relayUrl: string) =>
  ["dntls-names", relayUrl] as const;

/**
 * Community-scoped cache of relay-attested DNTLS pubkey→name mappings.
 * Refetches on a focused interval; a failed or 404 fetch yields an empty map.
 */
export function useDntlsNamesQuery() {
  const { activeCommunity } = useCommunities();
  const relayUrl = activeCommunity?.relayUrl ?? "";
  const refetchInterval = useFocusedRefetchInterval(
    DNTLS_NAMES_REFETCH_INTERVAL_MS,
  );

  return useQuery<DntlsNamesMap>({
    enabled: relayUrl.length > 0,
    queryKey: dntlsNamesQueryKey(relayUrl),
    queryFn: fetchDntlsNames,
    refetchInterval,
    staleTime: 30_000,
    retry: false,
  });
}

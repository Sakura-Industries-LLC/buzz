import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import {
  dntlsCredentialsStatus,
  subscribeDntlsCredentials,
} from "@/features/communities/dntlsConnector";
import { relayClient } from "@/shared/api/relayClient";

const credentialsQueryKey = ["dntls-credentials"] as const;

/** Observe the stored bundle and refresh identity labels after a reconnect. */
export function useDntlsCredentialsQuery() {
  const queryClient = useQueryClient();
  React.useEffect(() => {
    const unsubscribeCredentials = subscribeDntlsCredentials(() => {
      void queryClient.invalidateQueries({ queryKey: credentialsQueryKey });
    });
    const unsubscribeReconnect = relayClient.subscribeToReconnects(() => {
      void queryClient.invalidateQueries({ queryKey: credentialsQueryKey });
      void queryClient.invalidateQueries({ queryKey: ["dntls-names"] });
    });
    return () => {
      unsubscribeCredentials();
      unsubscribeReconnect();
    };
  }, [queryClient]);
  return useQuery({
    queryKey: credentialsQueryKey,
    queryFn: dntlsCredentialsStatus,
    staleTime: 30_000,
  });
}

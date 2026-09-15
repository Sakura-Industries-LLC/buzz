import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useCommunities } from "@/features/communities/useCommunities";
import {
  DNTLS_PENDING_REFETCH_INTERVAL_MS,
  dntlsPendingApplicationsQueryKey,
  removePendingDntlsApplication,
} from "@/features/community-members/lib/dntlsRequests";
import { dntlsNamesQueryKey } from "@/features/profile/useDntlsNames";
import {
  approveDntlsApplication,
  listPendingDntlsApplications,
  rejectDntlsApplication,
  type ListPendingDntlsApplicationsResult,
} from "@/shared/api/dntls";
import {
  addRelayMember,
  changeRelayMemberRole,
  getMyRelayMembership,
  getMyRelayMembershipLookup,
  listRelayMembers,
  removeRelayMember,
} from "@/shared/api/relayMembers";
import type { RelayMember } from "@/shared/api/types";

export const relayMembersQueryKey = ["relayMembers"] as const;
export const myRelayMembershipQueryKey = ["myRelayMembership"] as const;
export const myRelayMembershipLookupQueryKey = [
  "myRelayMembershipLookup",
] as const;
export { dntlsPendingApplicationsQueryKey, DNTLS_PENDING_REFETCH_INTERVAL_MS };

export function useRelayMembersQuery(enabled = true) {
  return useQuery({
    enabled,
    queryKey: relayMembersQueryKey,
    queryFn: listRelayMembers,
    staleTime: 30_000,
  });
}

export function useMyRelayMembershipQuery() {
  return useQuery({
    queryKey: myRelayMembershipQueryKey,
    queryFn: getMyRelayMembership,
    staleTime: 60_000,
  });
}

export function useMyRelayMembershipLookupQuery() {
  return useQuery({
    queryKey: myRelayMembershipLookupQueryKey,
    queryFn: getMyRelayMembershipLookup,
    staleTime: 60_000,
  });
}

export function useAddRelayMemberMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ pubkey, role }: { pubkey: string; role: string }) =>
      addRelayMember(pubkey, role),
    onMutate: async ({ pubkey, role }) => {
      await queryClient.cancelQueries({ queryKey: relayMembersQueryKey });
      const previous =
        queryClient.getQueryData<RelayMember[]>(relayMembersQueryKey);

      queryClient.setQueryData<RelayMember[]>(relayMembersQueryKey, (old) => [
        ...(old ?? []),
        {
          pubkey,
          role: role as RelayMember["role"],
          addedBy: null,
          createdAt: new Date().toISOString(),
        },
      ]);

      return { previous };
    },
    onError: (_err, _vars, context) => {
      if (context?.previous) {
        queryClient.setQueryData(relayMembersQueryKey, context.previous);
      }
    },
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: relayMembersQueryKey }),
        queryClient.invalidateQueries({ queryKey: myRelayMembershipQueryKey }),
        queryClient.invalidateQueries({
          queryKey: myRelayMembershipLookupQueryKey,
        }),
      ]);
    },
  });
}

export function useRemoveRelayMemberMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (pubkey: string) => removeRelayMember(pubkey),
    onMutate: async (pubkey) => {
      await queryClient.cancelQueries({ queryKey: relayMembersQueryKey });
      const previous =
        queryClient.getQueryData<RelayMember[]>(relayMembersQueryKey);

      queryClient.setQueryData<RelayMember[]>(relayMembersQueryKey, (old) =>
        old?.filter((m) => m.pubkey.toLowerCase() !== pubkey.toLowerCase()),
      );

      return { previous };
    },
    onError: (_err, _pubkey, context) => {
      if (context?.previous) {
        queryClient.setQueryData(relayMembersQueryKey, context.previous);
      }
    },
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: relayMembersQueryKey }),
        queryClient.invalidateQueries({ queryKey: myRelayMembershipQueryKey }),
        queryClient.invalidateQueries({
          queryKey: myRelayMembershipLookupQueryKey,
        }),
      ]);
    },
  });
}

export function useChangeRelayMemberRoleMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      pubkey,
      role,
      newRole,
    }: {
      pubkey: string;
      role?: string;
      newRole?: string;
    }) => changeRelayMemberRole(pubkey, role ?? newRole ?? "member"),
    onMutate: async ({ pubkey, role, newRole }) => {
      const nextRole = (role ?? newRole ?? "member") as RelayMember["role"];
      await queryClient.cancelQueries({ queryKey: relayMembersQueryKey });
      const previous =
        queryClient.getQueryData<RelayMember[]>(relayMembersQueryKey);

      queryClient.setQueryData<RelayMember[]>(relayMembersQueryKey, (old) =>
        old?.map((m) =>
          m.pubkey.toLowerCase() === pubkey.toLowerCase()
            ? { ...m, role: nextRole }
            : m,
        ),
      );

      return { previous };
    },
    onError: (_err, _vars, context) => {
      if (context?.previous) {
        queryClient.setQueryData(relayMembersQueryKey, context.previous);
      }
    },
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: relayMembersQueryKey }),
        queryClient.invalidateQueries({ queryKey: myRelayMembershipQueryKey }),
        queryClient.invalidateQueries({
          queryKey: myRelayMembershipLookupQueryKey,
        }),
      ]);
    },
  });
}

export function useDntlsPendingApplicationsQuery(enabled: boolean) {
  const { activeCommunity } = useCommunities();
  const relayUrl = activeCommunity?.relayUrl ?? "";

  return useQuery({
    enabled: enabled && relayUrl.length > 0,
    queryKey: dntlsPendingApplicationsQueryKey(relayUrl),
    queryFn: listPendingDntlsApplications,
    refetchInterval: DNTLS_PENDING_REFETCH_INTERVAL_MS,
    retry: false,
  });
}

export function useDecideDntlsApplicationMutation() {
  const queryClient = useQueryClient();
  const { activeCommunity } = useCommunities();
  const relayUrl = activeCommunity?.relayUrl ?? "";

  return useMutation({
    mutationFn: ({
      pubkey,
      decision,
    }: {
      pubkey: string;
      decision: "approve" | "reject";
    }) =>
      decision === "approve"
        ? approveDntlsApplication(pubkey)
        : rejectDntlsApplication(pubkey),
    onMutate: async ({ pubkey }) => {
      const pendingKey = dntlsPendingApplicationsQueryKey(relayUrl);
      const namesKey = dntlsNamesQueryKey(relayUrl);
      await queryClient.cancelQueries({ queryKey: pendingKey });
      const previousPending =
        queryClient.getQueryData<ListPendingDntlsApplicationsResult>(
          pendingKey,
        );

      queryClient.setQueryData<ListPendingDntlsApplicationsResult>(
        pendingKey,
        (old) => removePendingDntlsApplication(old, pubkey),
      );
      return { pendingKey, namesKey, previousPending };
    },
    onError: (_err, { pubkey }, context) => {
      const previous = context?.previousPending;
      if (!context || previous?.status !== "ok") return;
      const application = previous.applications.find(
        (entry) => entry.pubkey === pubkey,
      );
      if (!application) return;
      queryClient.setQueryData<ListPendingDntlsApplicationsResult>(
        context.pendingKey,
        (current) =>
          current?.status === "ok" &&
          !current.applications.some((entry) => entry.pubkey === pubkey)
            ? {
                status: "ok",
                applications: [...current.applications, application].sort(
                  (a, b) => a.createdAt - b.createdAt,
                ),
              }
            : current,
      );
    },
    onSettled: async (_data, _err, _vars, context) => {
      const pendingKey =
        context?.pendingKey ?? dntlsPendingApplicationsQueryKey(relayUrl);
      const namesKey = context?.namesKey ?? dntlsNamesQueryKey(relayUrl);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: pendingKey }),
        queryClient.invalidateQueries({ queryKey: namesKey }),
        queryClient.invalidateQueries({ queryKey: relayMembersQueryKey }),
      ]);
    },
  });
}

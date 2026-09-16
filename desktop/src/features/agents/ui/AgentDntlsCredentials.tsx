import * as React from "react";
import { listen } from "@tauri-apps/api/event";
import { toast } from "sonner";
import { useQueryClient } from "@tanstack/react-query";
import { managedAgentsQueryKey } from "@/features/agents/hooks";
import {
  cancelAgentCodeRequests,
  currentAgentCodeRequest,
  subscribeAgentCode,
  withAgentDntlsCode,
} from "@/features/agents/agentDntlsCode";
import { replaceManagedAgentDntlsCredentials } from "@/shared/api/tauri";
import type { ManagedAgent } from "@/shared/api/types";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/shared/ui/dialog";
import { DntlsCredentialCodeForm } from "@/features/communities/ui/DntlsCredentialCodeForm";

export function AgentDntlsCodeDialog() {
  const request = React.useSyncExternalStore(
    subscribeAgentCode,
    currentAgentCodeRequest,
  );
  React.useEffect(() => {
    const listener = listen<{ pubkey: string; message: string }>(
      "dntls-agent-credentials-error",
      ({ payload }) => {
        toast.error("Agent connection unavailable", {
          id: `dntls-agent-${payload.pubkey}`,
          description: payload.message,
        });
      },
    );
    return () => {
      void listener.then((unlisten) => unlisten());
    };
  }, []);
  const [busy, setBusy] = React.useState(false);
  React.useEffect(() => () => cancelAgentCodeRequests(), []);
  return (
    <Dialog
      open={request !== null}
      onOpenChange={(open) => {
        if (!open && !busy) request?.cancel();
      }}
    >
      <DialogContent
        className="max-w-lg"
        data-testid="agent-dntls-code-dialog"
        onEscapeKeyDown={(event) => {
          if (busy) event.preventDefault();
        }}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogTitle>Connect the agent's DNTLS name</DialogTitle>
        <DialogDescription className="sr-only">
          Paste a one-time code for a subname of your name. In the DNTLS Portal,
          open your name → Subnames → EXPORT → Export one-time code.
        </DialogDescription>
        {request ? (
          <DntlsCredentialCodeForm
            key={request.id}
            instruction="Paste a one-time code for a subname of your name (Portal → your name → Subnames → EXPORT → Export one-time code)."
            redeemCode={request.submit}
            onCancel={request.cancel}
            onBusyChange={setBusy}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

export function AgentDntlsIdentity({ agent }: { agent: ManagedAgent }) {
  const queryClient = useQueryClient();
  const community = agent.dntlsCommunity;
  if (!community) return null;
  return (
    <div
      className="flex flex-col gap-1 text-xs"
      data-testid={`agent-dntls-identity-${agent.pubkey}`}
    >
      {agent.dntlsName ? (
        <span className="break-all">DNTLS name: {agent.dntlsName}</span>
      ) : null}
      <Button
        size="sm"
        variant="outline"
        className="w-fit"
        onClick={(event) => {
          event.stopPropagation();
          void withAgentDntlsCode(community, async (code) => {
            const updated = await replaceManagedAgentDntlsCredentials(
              agent.pubkey,
              code,
              community,
            );
            queryClient.setQueryData<ManagedAgent[]>(
              managedAgentsQueryKey,
              (agents) =>
                agents?.map((item) =>
                  item.pubkey === updated.pubkey ? updated : item,
                ),
            );
            await queryClient.invalidateQueries({
              queryKey: managedAgentsQueryKey,
            });
          }).catch(() => {});
        }}
      >
        {agent.dntlsName ? "Replace…" : "Connect a name"}
      </Button>
    </div>
  );
}

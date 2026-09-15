import * as React from "react";
import { Ticket } from "lucide-react";

import { dntlsCommunityName, dntlsCredentialsStatus } from "@/features/communities/dntlsConnector";
import { useCommunityOnboarding } from "@/features/onboarding/communityOnboarding";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { StartupWindowDragRegion } from "@/shared/ui/StartupWindowDragRegion";
import { InviteRedeemForm } from "./InviteRedeemForm";

type AwaitingApprovalProps = {
  /** Active community relay — used as the target for bare-code invites. */
  activeRelayUrl: string;
  /** DNTLS FQDN or community display name; passed through `dntlsCommunityName`. */
  communityHint?: string | null;
  onChangeCommunity: () => void;
};

export function AwaitingApproval({
  activeRelayUrl,
  communityHint,
  onChangeCommunity,
}: AwaitingApprovalProps) {
  const communityOnboarding = useCommunityOnboarding();
  const [isInviteFormOpen, setIsInviteFormOpen] = React.useState(false);
  const [applicantName, setApplicantName] = React.useState<string | null>(null);

  const communityName = React.useMemo(() => {
    const hint = communityHint?.trim() ?? "";
    return dntlsCommunityName(hint) ?? (hint.length > 0 ? hint : "this community");
  }, [communityHint]);

  React.useEffect(() => {
    let cancelled = false;
    void dntlsCredentialsStatus()
      .then((status) => {
        if (cancelled) return;
        const name = status.user_name?.trim() || status.name?.trim() || null;
        setApplicantName(name);
      })
      .catch(() => {
        if (!cancelled) setApplicantName(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleInviteRedeem = React.useCallback(
    (relayWsUrl: string, code: string, policyReceipt?: string) => {
      communityOnboarding.start({
        source: "membership-recovery",
        relayUrl: relayWsUrl,
        inviteCode: code,
        policyReceipt,
      });
    },
    [communityOnboarding],
  );

  const applicantLabel = applicantName ?? "your name";

  return (
    <div
      className="flex min-h-dvh items-center justify-center bg-[radial-gradient(circle_at_top,hsl(var(--primary)/0.14),transparent_48%),linear-gradient(180deg,hsl(var(--background)),hsl(var(--muted)/0.55))] px-4 py-8"
      data-testid="awaiting-approval"
    >
      <StartupWindowDragRegion />
      <div className="w-full max-w-md rounded-[28px] border border-border/70 bg-background/92 p-8 shadow-2xl backdrop-blur-sm">
        <div className="space-y-3">
          <Badge variant="warning">Waiting</Badge>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/10">
              <Spinner aria-label="Waiting for approval" size={20} />
            </div>
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">
              Waiting for approval
            </h1>
          </div>
          <p className="text-sm leading-6 text-muted-foreground">
            An admin of {communityName} needs to approve {applicantLabel}. This
            screen updates on its own.
          </p>
        </div>

        <div className="mt-6 flex flex-col gap-2">
          {isInviteFormOpen ? (
            <InviteRedeemForm
              defaultRelayUrl={activeRelayUrl}
              error={null}
              isRedeeming={false}
              onCancel={() => setIsInviteFormOpen(false)}
              onRedeem={handleInviteRedeem}
            />
          ) : (
            <>
              <Button
                className="w-full text-muted-foreground hover:text-accent-foreground"
                data-testid="awaiting-approval-change-community"
                onClick={onChangeCommunity}
                type="button"
                variant="ghost"
              >
                Change community
              </Button>
              <button
                className="flex w-full items-center justify-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
                data-testid="awaiting-approval-invite"
                onClick={() => setIsInviteFormOpen(true)}
                type="button"
              >
                <Ticket className="h-4 w-4" />
                Use an invite code
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

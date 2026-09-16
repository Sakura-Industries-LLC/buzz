import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Users } from "lucide-react";

import {
  markCommunityOnboardingComplete,
  useCommunityOnboarding,
} from "@/features/onboarding/communityOnboarding";
import { initializeStarterChannels } from "@/features/onboarding/hooks";
import { useClaimInvite } from "@/features/onboarding/useClaimInvite";
import { startAwaitingApprovalRetry } from "@/features/onboarding/awaitingApprovalRetry";
import { membershipGateViewForError } from "@/features/onboarding/membershipGate";
import { CommunityChangeOverlay } from "@/features/communities/ui/CommunityChangeOverlay";
import {
  takePendingWelcomeChannelForDirectEntry,
  WELCOME_SURFACE_READY_EVENT,
} from "@/features/onboarding/welcome";
import { useAvatarPresentation } from "@/features/profile/avatarPresentationStore";
import { registerAvatarWhenReady } from "@/features/profile/avatarProfileSync";
import { profileQueryKey } from "@/features/profile/hooks";
import { ProfileAvatar } from "@/features/profile/ui/ProfileAvatar";
import {
  parseEmojiAvatarDataUrl,
  ProfileAvatarEditor,
} from "@/features/profile/ui/ProfileAvatarEditor";
import { dntlsCredentialsStatus } from "@/features/communities/dntlsConnector";
import { getProfile, updateProfile } from "@/shared/api/tauriProfiles";
import { getIdentity, importIdentity } from "@/shared/api/tauriIdentity";
import { relayClient } from "@/shared/api/relayClient";
import { subscribeToTauriErrors } from "@/shared/api/tauriErrors";
import type { Profile } from "@/shared/api/types";
import { cn } from "@/shared/lib/cn";
import { useSystemColorScheme } from "@/shared/theme/useSystemColorScheme";
import { Button } from "@/shared/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/shared/ui/dialog";
import { Input } from "@/shared/ui/input";
import { MembershipDenied } from "./MembershipDenied";
import { AwaitingApproval } from "./AwaitingApproval";
import { StartupWindowDragRegion } from "@/shared/ui/StartupWindowDragRegion";
import {
  ONBOARDING_PRIMARY_CTA_CLASS,
  OnboardingChrome,
} from "./OnboardingChrome";
import { OnboardingFooter, OnboardingFooterProvider } from "./OnboardingFooter";
import {
  type OnboardingTransitionDirection,
  OnboardingSlideTransition,
} from "./OnboardingSlideTransition";

/** Fade duration for the "entering" curtain over the mounting app. */
const ENTERING_CURTAIN_FADE_MS = 500;
/**
 * Safety valve: if Welcome never reports ready (slow relay, failed query),
 * fade anyway rather than stranding the user on the onboarding screen.
 */
const ENTERING_CURTAIN_MAX_WAIT_MS = 8_000;

const NEUTRAL_EMOJI_PICKER_THEME_VARS = {
  "--buzz-emoji-picker-rgb-background":
    "var(--buzz-onboarding-emoji-picker-background)",
  "--buzz-emoji-picker-rgb-color": "var(--buzz-onboarding-emoji-picker-color)",
  "--buzz-emoji-picker-rgb-input": "var(--buzz-onboarding-emoji-picker-input)",
} as React.CSSProperties;

function AvatarCircle({
  avatarUrl,
  onClick,
  previewName,
  triggerRef,
}: {
  avatarUrl: string;
  onClick: () => void;
  previewName: string;
  triggerRef?: React.Ref<HTMLButtonElement>;
}) {
  const emojiAvatar = parseEmojiAvatarDataUrl(avatarUrl);
  const presentation = useAvatarPresentation(avatarUrl);
  const hasAvatar =
    avatarUrl.trim().length > 0 && presentation?.state !== "failed";

  return (
    <button
      aria-label={hasAvatar ? "Change your avatar" : "Add an avatar"}
      className="group block shrink-0 rounded-full"
      data-testid="community-avatar-open"
      onClick={onClick}
      ref={triggerRef}
      type="button"
    >
      {emojiAvatar ? (
        <span
          className="flex h-36 w-36 items-center justify-center overflow-hidden rounded-full text-5xl shadow-xs"
          style={{ backgroundColor: emojiAvatar.color }}
        >
          {emojiAvatar.emoji}
        </span>
      ) : hasAvatar ? (
        <ProfileAvatar
          avatarUrl={avatarUrl}
          className="h-36 w-36 rounded-full text-4xl"
          label={previewName}
          testId="community-avatar-circle"
        />
      ) : (
        <span
          className="flex h-36 w-36 items-center justify-center rounded-full bg-white/30 text-[var(--buzz-onboarding-backup-ink)] transition-colors group-hover:bg-white/40"
          data-testid="community-avatar-empty"
        >
          <Plus className="h-7 w-7" aria-hidden="true" />
        </span>
      )}
    </button>
  );
}

function LoadingDots({ label }: { label: string }) {
  return (
    <span
      aria-label={label}
      className="inline-flex items-center justify-center gap-1"
      data-testid="community-team-intro-loading-dots"
      role="status"
    >
      {[0, 1, 2].map((index) => (
        <span
          aria-hidden="true"
          className="h-1.5 w-1.5 animate-bounce rounded-full bg-current motion-reduce:animate-none"
          key={index}
          style={{ animationDelay: `${index * 120}ms` }}
        />
      ))}
    </span>
  );
}

export function CommunityOnboardingFlow({
  onCancel,
  onConnect,
}: {
  onCancel: () => void;
  onConnect: () => void;
}) {
  const { transaction, update, clear } = useCommunityOnboarding();
  const queryClient = useQueryClient();
  const systemColorScheme = useSystemColorScheme();
  const [displayName, setDisplayName] = React.useState("");
  const [avatarUrl, setAvatarUrl] = React.useState("");
  const [localAvatarPreviewUrl, setLocalAvatarPreviewUrl] = React.useState<
    string | null
  >(null);
  const [avatarSquishKey, setAvatarSquishKey] = React.useState(0);
  const [transitionDirection, setTransitionDirection] =
    React.useState<OnboardingTransitionDirection>("forward");
  const avatarPresentation = useAvatarPresentation(avatarUrl);
  const [isUploadingAvatar, setIsUploadingAvatar] = React.useState(false);
  const [isAvatarEditorOpen, setIsAvatarEditorOpen] = React.useState(false);
  const [animatedPreviewEl, setAnimatedPreviewEl] =
    React.useState<HTMLDivElement | null>(null);
  const [isAnimatedPreviewActive, setIsAnimatedPreviewActive] =
    React.useState(false);
  const [animatedPreviewCaption, setAnimatedPreviewCaption] = React.useState<
    string | null
  >(null);
  const [isPending, setIsPending] = React.useState(false);
  const checkedProfileTransactionRef = React.useRef<string | null>(null);
  const [starterChannelFailureCount, setStarterChannelFailureCount] =
    React.useState(0);
  const [deniedPubkey, setDeniedPubkey] = React.useState("");
  const [isMembershipDenied, setIsMembershipDenied] = React.useState(false);
  const [isAwaitingApproval, setIsAwaitingApproval] = React.useState(false);
  const awaitingResumeRef = React.useRef<"dntls-skip" | "save-profile">(
    "dntls-skip",
  );
  const [isCommunityChangeOpen, setIsCommunityChangeOpen] =
    React.useState(false);
  const [isCurtainFading, setIsCurtainFading] = React.useState(false);
  const nameInputRef = React.useRef<HTMLInputElement | null>(null);
  const avatarTriggerRef = React.useRef<HTMLButtonElement | null>(null);
  const avatarEditorContentRef = React.useRef<HTMLDivElement | null>(null);
  const [avatarEditorDialogHeight, setAvatarEditorDialogHeight] =
    React.useState<number | null>(null);
  const animateEmojiAvatarChange = React.useCallback(() => {
    setAvatarSquishKey((key) => key + 1);
  }, []);

  useClaimInvite();

  React.useEffect(() => {
    if (transaction?.stage === "connecting") onConnect();
  }, [onConnect, transaction?.stage]);

  // "Entering" curtain: the app is mounting on the Welcome route underneath.
  // Fade out when Welcome reports its first settled render — or after a
  // safety timeout so a slow load can never strand the user on this screen.
  const isEnteringStage = transaction?.stage === "entering";
  React.useEffect(() => {
    if (!isEnteringStage) return;

    let fadeTimer: number | null = null;
    const beginFade = () => {
      if (fadeTimer !== null) return;
      setIsCurtainFading(true);
      fadeTimer = window.setTimeout(() => {
        clear();
      }, ENTERING_CURTAIN_FADE_MS);
    };

    window.addEventListener(WELCOME_SURFACE_READY_EVENT, beginFade);
    const safetyTimer = window.setTimeout(
      beginFade,
      ENTERING_CURTAIN_MAX_WAIT_MS,
    );
    return () => {
      window.removeEventListener(WELCOME_SURFACE_READY_EVENT, beginFade);
      window.clearTimeout(safetyTimer);
      if (fadeTimer !== null) window.clearTimeout(fadeTimer);
    };
  }, [clear, isEnteringStage]);

  const retry = () =>
    update({
      stage: transaction?.inviteCode ? "claiming" : "connecting",
      error: undefined,
    });
  const relayUrl = transaction?.relayUrl;
  const finish = React.useCallback(async () => {
    if (!relayUrl) return;
    const identity = await getIdentity();
    markCommunityOnboardingComplete(identity.pubkey, relayUrl);
    clear();
  }, [clear, relayUrl]);
  const routeMembershipError = React.useCallback(async (error: unknown) => {
    const view = membershipGateViewForError(error);
    if (view == null) return false;
    setIsMembershipDenied(view === "membership-denied");
    setIsAwaitingApproval(view === "awaiting-approval");
    setIsAvatarEditorOpen(false);
    const identity = await getIdentity().catch(() => null);
    setDeniedPubkey(identity?.pubkey ?? "");
    return true;
  }, []);
  // biome-ignore lint/correctness/useExhaustiveDependencies: only the current transaction owns in-flight HTTP failures.
  React.useLayoutEffect(() => {
    if (!transaction?.id) return;
    return subscribeToTauriErrors((error) => void routeMembershipError(error));
  }, [routeMembershipError, transaction?.id, transaction?.relayUrl]);
  const finalize = React.useCallback(async () => {
    if (isPending || !relayUrl) return;
    setIsPending(true);
    update({ stage: "finalizing", error: undefined });
    try {
      await relayClient.preconnect();
      const identity = await getIdentity();
      const result = await initializeStarterChannels(queryClient, {
        focus: true,
        pubkey: identity.pubkey,
        communityScope: transaction?.dntlsName ?? relayUrl,
      });
      if (!result.ok) throw new Error(result.reason);
      if (result.focusChannelId) {
        // Direct entry: point the router at the Welcome channel *before* the
        // app mounts, so it never lands on Home first. Consume the pending
        // entry — it exists for the Home-route fallback, and leaving it would
        // yank a later Home visit back to Welcome.
        takePendingWelcomeChannelForDirectEntry();
        window.location.hash = `/channels/${result.focusChannelId}`;
        markCommunityOnboardingComplete(identity.pubkey, relayUrl);
        // Keep this screen mounted as a curtain over the loading app; the
        // "entering" stage fades it out once Welcome reports ready.
        setIsAwaitingApproval(false);
        update({ stage: "entering", error: undefined });
        return;
      }
      await finish();
    } catch (error) {
      if (await routeMembershipError(error)) {
        setIsPending(false);
        return;
      }
      setIsAwaitingApproval(false);
      setStarterChannelFailureCount((count) => count + 1);
      update({
        error: error instanceof Error ? error.message : String(error),
      });
      setIsPending(false);
    }
  }, [
    finish,
    isPending,
    queryClient,
    relayUrl,
    routeMembershipError,
    transaction?.dntlsName,
    update,
  ]);

  const backToProfile = React.useCallback(() => {
    if (isPending) return;
    setStarterChannelFailureCount(0);
    setTransitionDirection("backward");
    update({ stage: "profile", error: undefined });
  }, [isPending, update]);

  const isProfileStage = transaction?.stage === "profile";
  const publishProfileDraft = React.useCallback(
    async (targetRelayUrl: string) => {
      const candidateAvatarUrl = avatarUrl.trim();
      const presentationState = avatarPresentation?.state;
      const shouldSaveCandidate =
        candidateAvatarUrl.length > 0 &&
        presentationState !== "failed" &&
        presentationState !== "pending";
      const deferredAvatar =
        candidateAvatarUrl && presentationState && presentationState !== "ready"
          ? registerAvatarWhenReady({
              avatarUrl: candidateAvatarUrl,
              relayUrl: targetRelayUrl,
            })
          : null;
      try {
        const profile = await updateProfile({
          displayName: displayName.trim(),
          avatarUrl: shouldSaveCandidate ? candidateAvatarUrl : undefined,
        });
        deferredAvatar?.release({
          expectedPubkey: profile.pubkey,
          expectedAvatarUrl: profile.avatarUrl,
        });
      } catch (error) {
        deferredAvatar?.cancel();
        throw error;
      }
    },
    [avatarUrl, avatarPresentation?.state, displayName],
  );
  const tryEnterAfterApproval = React.useCallback(
    async (isCurrent: () => boolean) => {
      if (!transaction) return "pending";
      try {
        await relayClient.preconnect();
        if (!isCurrent()) return "pending";
        await getProfile();
      } catch (error) {
        return membershipGateViewForError(error) === "membership-denied"
          ? "denied"
          : "pending";
      }
      if (!isCurrent()) return "pending";
      if (awaitingResumeRef.current === "save-profile") {
        const name = displayName.trim();
        if (!name) return "pending";
        try {
          await publishProfileDraft(transaction.relayUrl);
        } catch (error) {
          const view = membershipGateViewForError(error);
          if (view === "membership-denied") return "denied";
          return "pending";
        }
      } else if (transaction.dntlsName) {
        const status = await dntlsCredentialsStatus().catch(() => null);
        if (!isCurrent()) return "pending";
        const connectedName = status?.name?.trim();
        if (!connectedName) {
          if (!isCurrent()) return "pending";
          update({ stage: "profile", error: undefined }, transaction.id);
          setIsAwaitingApproval(false);
          return "continue";
        }
        try {
          await updateProfile({ displayName: connectedName });
        } catch (error) {
          const view = membershipGateViewForError(error);
          if (view === "membership-denied") return "denied";
          return "pending";
        }
      } else {
        if (!isCurrent()) return "pending";
        update({ stage: "profile", error: undefined }, transaction.id);
        setIsAwaitingApproval(false);
        return "continue";
      }
      if (!isCurrent()) return "pending";
      update({ error: undefined }, transaction.id);
      setIsAwaitingApproval(false);
      setTransitionDirection("forward");
      await finalize();
      return "pending";
    },
    [displayName, publishProfileDraft, transaction, finalize, update],
  );
  const approvalAttemptRef = React.useRef(tryEnterAfterApproval);
  React.useEffect(() => {
    approvalAttemptRef.current = tryEnterAfterApproval;
  }, [tryEnterAfterApproval]);
  // Skip the display-name step when the relay already has a profile, or when
  // this is a DNTLS community: the verified DNTLS name the user chose is
  // their name, so it is published as the display name without asking.
  React.useEffect(() => {
    if (!isProfileStage || !transaction) return;
    if (checkedProfileTransactionRef.current === transaction.id) return;

    checkedProfileTransactionRef.current = transaction.id;
    const skipToTeam = () => {
      setTransitionDirection("forward");
      update({ stage: "team-intro", error: undefined }, transaction.id);
    };
    void (async () => {
      let profile: Profile | null = null;
      try {
        profile = await getProfile();
        setDisplayName((prev) => prev || profile?.displayName || "");
        setAvatarUrl((prev) => prev || profile?.avatarUrl || "");
      } catch (error) {
        if (await routeMembershipError(error)) {
          awaitingResumeRef.current = "dntls-skip";
          return;
        }
      }
      if (profile?.hasProfileEvent) {
        skipToTeam();
        return;
      }
      if (!transaction.dntlsName) return;
      const status = await dntlsCredentialsStatus().catch(() => null);
      const connectedName = status?.name?.trim();
      if (!connectedName) return;
      try {
        await updateProfile({ displayName: connectedName });
      } catch (error) {
        if (await routeMembershipError(error)) {
          awaitingResumeRef.current = "dntls-skip";
          return;
        }
        // Publishing failed for another reason: fall through to the manual
        // step, seeded with the name so the user only has to confirm.
        setDisplayName((prev) => (prev === "" ? connectedName : prev));
        return;
      }
      skipToTeam();
    })();
  }, [isProfileStage, routeMembershipError, transaction, update]);
  const isTeamStage =
    transaction?.stage === "team-intro" ||
    transaction?.stage === "finalizing" ||
    transaction?.stage === "entering";

  React.useLayoutEffect(() => {
    if (isProfileStage && !isAvatarEditorOpen) {
      nameInputRef.current?.focus();
    }
  }, [isAvatarEditorOpen, isProfileStage]);

  React.useLayoutEffect(() => {
    if (!isAvatarEditorOpen) {
      setAvatarEditorDialogHeight(null);
      return;
    }

    const content = avatarEditorContentRef.current;
    if (!content) return;

    const updateHeight = () => {
      setAvatarEditorDialogHeight(content.getBoundingClientRect().height + 64);
    };
    updateHeight();

    const resizeObserver = new ResizeObserver(updateHeight);
    resizeObserver.observe(content);
    return () => resizeObserver.disconnect();
  }, [isAvatarEditorOpen]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: a replacement transaction must discard the previous membership gate.
  React.useEffect(() => {
    setIsAwaitingApproval(false);
    setIsMembershipDenied(false);
  }, [transaction?.id]);
  React.useEffect(() => {
    if (transaction?.stage === "claiming") {
      setIsAwaitingApproval(false);
      setIsMembershipDenied(false);
    }
  }, [transaction?.stage]);
  React.useEffect(() => {
    if (!transaction?.error) return;
    if (
      transaction.stage === "connecting" ||
      transaction.stage === "claiming"
    ) {
      awaitingResumeRef.current = "dntls-skip";
    }
    void routeMembershipError(transaction.error);
  }, [routeMembershipError, transaction?.error, transaction?.stage]);

  const approvalTransactionId = transaction?.id;
  const approvalRelayUrl = transaction?.relayUrl;

  // biome-ignore lint/correctness/useExhaustiveDependencies: changing the relay cancels in-flight approval results even when the transaction ID stays the same.
  React.useEffect(() => {
    if (!isAwaitingApproval || !approvalTransactionId) return;
    let cancelled = false;

    const showDenied = () => {
      if (cancelled) return;
      setIsAwaitingApproval(false);
      setIsMembershipDenied(true);
    };
    const stop = startAwaitingApprovalRetry({
      attempt: () => approvalAttemptRef.current(() => !cancelled),
      onContinue: () => {},
      onDenied: showDenied,
    });

    return () => {
      cancelled = true;
      stop();
    };
  }, [isAwaitingApproval, approvalTransactionId, approvalRelayUrl]);

  if (!transaction) return null;

  if (isMembershipDenied) {
    return (
      <>
        <MembershipDenied
          activeRelayUrl={transaction.relayUrl}
          dntlsDeclined={Boolean(transaction.dntlsName)}
          onBack={() => setIsMembershipDenied(false)}
          onChangeCommunity={() => setIsCommunityChangeOpen(true)}
          onImportKey={async (nsec) => {
            const identity = await importIdentity(nsec);
            relayClient.disconnect();
            queryClient.setQueryData(["identity"], identity);
            queryClient.removeQueries({ queryKey: profileQueryKey });
            setIsMembershipDenied(false);
            update({ stage: "connecting", error: undefined });
          }}
          onRetry={() => {
            setIsMembershipDenied(false);
            update({ stage: "connecting", error: undefined });
          }}
          pubkey={deniedPubkey}
        />
        {isCommunityChangeOpen ? (
          <CommunityChangeOverlay
            onClose={() => setIsCommunityChangeOpen(false)}
            onUpdated={(communityName, updatedRelayUrl) => {
              update({
                communityName,
                relayUrl: updatedRelayUrl,
                stage: "connecting",
                error: undefined,
              });
              setIsMembershipDenied(false);
              setIsAwaitingApproval(false);
            }}
          />
        ) : null}
      </>
    );
  }

  if (isAwaitingApproval) {
    return (
      <>
        <AwaitingApproval
          activeRelayUrl={transaction.relayUrl}
          communityHint={transaction.dntlsName ?? transaction.communityName}
          onChangeCommunity={() => setIsCommunityChangeOpen(true)}
        />
        {isCommunityChangeOpen ? (
          <CommunityChangeOverlay
            onClose={() => setIsCommunityChangeOpen(false)}
            onUpdated={(communityName, updatedRelayUrl) => {
              update({
                communityName,
                relayUrl: updatedRelayUrl,
                stage: "connecting",
                error: undefined,
              });
              setIsAwaitingApproval(false);
              setIsMembershipDenied(false);
            }}
          />
        ) : null}
      </>
    );
  }

  const saveProfile = async () => {
    if (!displayName.trim()) return;
    setIsPending(true);
    try {
      await publishProfileDraft(transaction.relayUrl);
      setTransitionDirection("forward");
      update({ stage: "team-intro", error: undefined });
    } catch (error) {
      if (await routeMembershipError(error)) {
        awaitingResumeRef.current = "save-profile";
        return;
      }
      update({ error: error instanceof Error ? error.message : String(error) });
    } finally {
      setIsPending(false);
    }
  };

  return (
    <div
      className={cn(
        "buzz-onboarding-neutral-theme buzz-startup-shell flex h-dvh justify-center overflow-y-auto px-4 text-foreground",
        isProfileStage || isTeamStage
          ? "items-start pb-36 pt-[106px]"
          : "items-stretch",
        isCurtainFading &&
          "pointer-events-none opacity-0 transition-opacity ease-out motion-reduce:transition-none",
      )}
      data-system-color-scheme={systemColorScheme}
      data-testid="community-onboarding-flow"
      style={
        isCurtainFading
          ? { transitionDuration: `${ENTERING_CURTAIN_FADE_MS}ms` }
          : undefined
      }
    >
      <StartupWindowDragRegion />
      {isProfileStage || isTeamStage ? (
        <OnboardingChrome current={isTeamStage ? 7 : 6} />
      ) : null}
      <OnboardingFooterProvider
        backAction={
          isProfileStage
            ? {
                disabled: isPending || isUploadingAvatar,
                onClick: onCancel,
                testId: "community-profile-back",
              }
            : isTeamStage
              ? {
                  disabled: isPending || transaction.stage === "entering",
                  onClick: backToProfile,
                  testId: "community-team-intro-back",
                }
              : undefined
        }
      >
        <OnboardingSlideTransition
          direction={transitionDirection}
          transitionKey={`community-${isProfileStage ? "profile" : isTeamStage ? "team" : transaction.stage}-${transitionDirection}`}
        >
          <div
            className={cn(
              "relative mx-auto w-full text-center",
              isProfileStage
                ? "buzz-onboarding-step-frame flex max-w-[500px] flex-col items-center"
                : isTeamStage
                  ? "buzz-onboarding-step-frame flex max-w-[760px] flex-col items-center"
                  : "flex min-h-dvh max-w-[560px] flex-col justify-center py-8",
            )}
            data-testid="community-onboarding-body"
          >
            {transaction.stage === "claiming" ||
            transaction.stage === "connecting" ? (
              <>
                <Users className="mx-auto h-10 w-10" />
                <h1 className="mt-5 text-title font-normal">
                  Joining {transaction.communityName}
                </h1>
                <p className="mt-3 text-sm text-foreground/80">
                  {transaction.error ??
                    (transaction.stage === "claiming"
                      ? "Accepting your invite…"
                      : "Connecting securely…")}
                </p>
                <div className="mt-6 flex justify-center gap-3">
                  {transaction.error ? (
                    <Button className="rounded-full px-6" onClick={retry}>
                      Retry
                    </Button>
                  ) : null}
                  <Button
                    className="rounded-full bg-foreground/10 px-5 hover:bg-foreground/15"
                    onClick={onCancel}
                    variant="ghost"
                  >
                    Cancel
                  </Button>
                </div>
              </>
            ) : isProfileStage ? (
              <>
                <div
                  className={cn(
                    "flex min-h-0 w-full flex-1 flex-col transition-[filter,opacity] duration-200 ease-out",
                    isAvatarEditorOpen &&
                      "pointer-events-none opacity-45 blur-[3px]",
                  )}
                  data-testid="community-profile-main"
                >
                  <div className="shrink-0">
                    <h1 className="text-title font-normal">
                      Build your profile
                    </h1>
                    <p className="mx-auto mt-3 max-w-[380px] text-sm leading-6 text-foreground/80">
                      Add a name and avatar. They’ll show up on your messages,
                      reactions, and agent handoffs.
                    </p>
                  </div>
                  <div className="flex min-h-0 w-full flex-1 flex-col items-center justify-center pt-8">
                    <AvatarCircle
                      avatarUrl={avatarUrl}
                      onClick={() => setIsAvatarEditorOpen(true)}
                      previewName={displayName.trim() || "Your profile"}
                      triggerRef={avatarTriggerRef}
                    />
                    <label
                      className="mt-7 block w-full max-w-[412px] text-left"
                      htmlFor="community-display-name"
                    >
                      <span className="mb-2 block pl-4 text-sm text-foreground">
                        Your username
                      </span>
                      <Input
                        aria-label="Community username"
                        autoCapitalize="none"
                        autoComplete="username"
                        autoCorrect="off"
                        className="h-14 rounded-2xl border-[color:rgb(var(--buzz-onboarding-avatar-control-fg)_/_0.28)] bg-[rgb(var(--buzz-onboarding-avatar-dialog-bg)/0.95)] px-5 text-sm shadow-none placeholder:text-muted-foreground/60 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[color:rgb(var(--buzz-onboarding-avatar-control-fg)_/_0.5)] md:text-sm"
                        data-testid="community-profile-name-key"
                        disabled={isPending || isUploadingAvatar}
                        id="community-display-name"
                        onChange={(event) => setDisplayName(event.target.value)}
                        placeholder="Enter your username here"
                        ref={nameInputRef}
                        spellCheck={false}
                        type="text"
                        value={displayName}
                      />
                    </label>
                  </div>
                  {transaction.error ? (
                    <p className="mt-4 text-sm text-destructive">
                      {transaction.error}
                    </p>
                  ) : null}
                </div>
                <OnboardingFooter
                  className={cn(
                    "transition-[filter,opacity] duration-200 ease-out",
                    isAvatarEditorOpen &&
                      "pointer-events-none opacity-45 blur-[3px]",
                  )}
                >
                  <Button
                    className={`${ONBOARDING_PRIMARY_CTA_CLASS} w-20`}
                    data-testid="community-profile-next"
                    disabled={
                      !displayName.trim() || isPending || isUploadingAvatar
                    }
                    onClick={() => void saveProfile()}
                    type="button"
                  >
                    Next
                  </Button>
                </OnboardingFooter>
                <Dialog
                  onOpenChange={(open) => setIsAvatarEditorOpen(open)}
                  open={isAvatarEditorOpen}
                >
                  <DialogContent
                    className="buzz-onboarding-neutral-theme w-[min(calc(100vw-2rem),920px)] max-w-[920px] gap-0 overflow-hidden rounded-[18px] bg-[rgb(var(--buzz-onboarding-avatar-dialog-bg))] px-8 pb-6 pt-10 text-sm text-foreground shadow-[0_28px_90px_rgb(var(--buzz-onboarding-avatar-dialog-shadow)_/_0.28),0_8px_28px_rgb(var(--buzz-onboarding-avatar-dialog-shadow)_/_0.18)] transition-[height] duration-[250ms] ease-out"
                    closeButtonClassName="right-6 top-6 h-10 w-10 rounded-full bg-[rgb(var(--buzz-onboarding-avatar-action-bg))] text-[rgb(var(--buzz-onboarding-avatar-action-fg))] hover:bg-[rgb(var(--buzz-onboarding-avatar-action-bg)/0.9)] hover:text-[rgb(var(--buzz-onboarding-avatar-action-fg))]"
                    data-system-color-scheme="light"
                    data-testid="community-avatar-editor-key-frame"
                    onCloseAutoFocus={(event) => {
                      event.preventDefault();
                      avatarTriggerRef.current?.focus();
                    }}
                    overlayVariant="transparent"
                    style={
                      avatarEditorDialogHeight === null
                        ? undefined
                        : { height: avatarEditorDialogHeight }
                    }
                  >
                    <DialogTitle className="sr-only">
                      Edit your avatar
                    </DialogTitle>
                    <div
                      className="grid items-center gap-8 md:grid-cols-[240px_minmax(0,1fr)]"
                      ref={avatarEditorContentRef}
                    >
                      <div
                        className="flex min-h-[320px] flex-col items-center justify-center gap-3 px-6 py-8"
                        data-testid="community-avatar-live-preview-panel"
                      >
                        <div className="relative h-48 w-48">
                          <div
                            className="pointer-events-none absolute inset-0 z-10"
                            data-testid="community-avatar-animated-preview-slot"
                            ref={setAnimatedPreviewEl}
                          />
                          {isAnimatedPreviewActive
                            ? null
                            : (() => {
                                if (localAvatarPreviewUrl) {
                                  return (
                                    <ProfileAvatar
                                      avatarUrl={localAvatarPreviewUrl}
                                      className="h-full w-full rounded-full text-5xl"
                                      label={
                                        displayName.trim() || "Your profile"
                                      }
                                      testId="community-avatar-live-preview"
                                    />
                                  );
                                }
                                const emojiAvatar =
                                  parseEmojiAvatarDataUrl(avatarUrl);
                                return emojiAvatar ? (
                                  <div
                                    aria-label={`${displayName.trim() || "Your profile"} avatar`}
                                    className="flex h-full w-full items-center justify-center overflow-hidden rounded-full text-6xl shadow-xs"
                                    data-testid="community-avatar-live-preview"
                                    role="img"
                                    style={{
                                      backgroundColor: emojiAvatar.color,
                                    }}
                                  >
                                    <span
                                      className={cn(
                                        avatarSquishKey > 0 &&
                                          "buzz-avatar-squish",
                                      )}
                                      data-testid="community-avatar-live-preview-emoji"
                                      key={avatarSquishKey}
                                    >
                                      {emojiAvatar.emoji}
                                    </span>
                                  </div>
                                ) : (
                                  <ProfileAvatar
                                    avatarUrl={
                                      localAvatarPreviewUrl || avatarUrl || null
                                    }
                                    className="h-full w-full rounded-full text-5xl"
                                    label={displayName.trim() || "Your profile"}
                                    testId="community-avatar-live-preview"
                                  />
                                );
                              })()}
                        </div>
                        {animatedPreviewCaption ? (
                          <p className="text-center text-sm text-muted-foreground">
                            {animatedPreviewCaption}
                          </p>
                        ) : null}
                      </div>
                      <ProfileAvatarEditor
                        animatedPreviewContainer={animatedPreviewEl}
                        avatarUrl={avatarUrl}
                        disabled={isPending}
                        donePending={isUploadingAvatar}
                        emojiPickerTheme="auto"
                        emojiPickerThemeVars={NEUTRAL_EMOJI_PICKER_THEME_VARS}
                        onDone={() => setIsAvatarEditorOpen(false)}
                        onAnimatedPreviewActiveChange={
                          setIsAnimatedPreviewActive
                        }
                        onAnimatedPreviewCaptionChange={
                          setAnimatedPreviewCaption
                        }
                        onEmojiAvatarChange={animateEmojiAvatarChange}
                        onLocalPreviewChange={setLocalAvatarPreviewUrl}
                        onUploadingChange={setIsUploadingAvatar}
                        onUrlChange={setAvatarUrl}
                        presentation="onboarding-modal"
                        previewName={displayName.trim() || "Your profile"}
                        testIdPrefix="community-avatar"
                      />
                    </div>
                  </DialogContent>
                </Dialog>
              </>
            ) : (
              <>
                <h1 className="text-title font-normal">
                  Your community is ready
                </h1>
                <p className="mx-auto mt-3 max-w-[400px] text-sm leading-6 text-foreground/80">
                  Your private Welcome channel is ready. You can create agents
                  from templates when you need them. Each agent in a DNTLS
                  community needs its own name.
                </p>
                <div className="flex-1" />
                {transaction.error ? (
                  <p className="text-sm text-destructive">
                    {transaction.error}
                    {starterChannelFailureCount === 1 ? " Try again." : null}
                  </p>
                ) : null}
                <OnboardingFooter>
                  <Button
                    className={ONBOARDING_PRIMARY_CTA_CLASS}
                    data-testid="community-team-intro-enter"
                    disabled={isPending || transaction.stage === "entering"}
                    onClick={() => void finalize()}
                  >
                    {isPending || transaction.stage === "entering" ? (
                      <LoadingDots label="Preparing Welcome" />
                    ) : (
                      "Take me to Buzz"
                    )}
                  </Button>
                  {starterChannelFailureCount >= 2 ? (
                    <Button
                      className="h-9 rounded-full px-5 hover:bg-foreground/10"
                      data-testid="community-team-intro-skip"
                      disabled={isPending || transaction.stage === "entering"}
                      onClick={() => void finish()}
                      variant="ghost"
                    >
                      Skip for now
                    </Button>
                  ) : null}
                </OnboardingFooter>
              </>
            )}
          </div>
        </OnboardingSlideTransition>
      </OnboardingFooterProvider>
    </div>
  );
}

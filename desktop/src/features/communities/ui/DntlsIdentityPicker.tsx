import * as React from "react";
import { openUrl } from "@tauri-apps/plugin-opener";

import {
  bindDntlsIdentity,
  getDntlsResolverStatus,
  isDntlsError,
  listDntlsIdentities,
  type DntlsBound,
  type DntlsIdentity,
} from "@/features/communities/dntlsConnector";
import { cn } from "@/shared/lib/cn";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";

const RESOLVER_DOWNLOADS_URL = "https://preview.dntls.net/downloads";
const UNAVAILABLE_COPY =
  "Install and open the DNTLS Local Trust Resolver, then try again";
const NO_IDENTITY_COPY =
  "Open the Local Trust Resolver and sign in to your DNTLS names first";
const UNRECOGNIZED_BUILD_COPY =
  "This build of Buzz cannot be recognized by the Local Trust Resolver";
const UNRECOGNIZED_COPY =
  "The Local Trust Resolver did not recognize this copy of Buzz";
const LIST_CONSENT_COPY =
  "The Local Trust Resolver will ask you to allow this";
const BIND_CONSENT_COPY =
  "The Local Trust Resolver will ask which key to give Buzz";
const DENIED_COPY = "You didn't allow it";
const EMPTY_COPY = "No names are stored on this machine yet";

type PickerProps = {
  onBound: (name: string) => void;
  onCancel?: () => void;
  onSkip?: () => void;
};

type PickerPhase =
  | { kind: "probing" }
  | { kind: "unavailable" }
  | { kind: "no_identity" }
  | { kind: "unrecognized"; message: string }
  | { kind: "ready" }
  | { kind: "listing" }
  | { kind: "empty" }
  | {
      kind: "list";
      identities: DntlsIdentity[];
      selectedName: string | null;
    }
  | {
      kind: "binding";
      identities: DntlsIdentity[];
      selectedName: string;
    }
  | { kind: "bound"; bound: DntlsBound; selectedFqdn: string };

function errorCode(error: unknown): string | null {
  return isDntlsError(error) ? error.code : null;
}

function errorMessage(error: unknown): string {
  if (isDntlsError(error)) return error.message;
  if (error instanceof Error) return error.message;
  return "Something went wrong talking to the Local Trust Resolver.";
}

function canUseIdentity(identity: DntlsIdentity): boolean {
  return identity.has_private_identity;
}

export function DntlsIdentityPicker({
  onBound,
  onCancel,
  onSkip,
}: PickerProps) {
  const [phase, setPhase] = React.useState<PickerPhase>({ kind: "probing" });
  const [notice, setNotice] = React.useState<string | null>(null);
  const cancelledRef = React.useRef(false);

  React.useEffect(() => {
    cancelledRef.current = false;
    return () => {
      cancelledRef.current = true;
    };
  }, []);

  const probeResolver = React.useCallback(async () => {
    setNotice(null);
    setPhase({ kind: "probing" });
    try {
      const status = await getDntlsResolverStatus();
      if (cancelledRef.current) return;
      if (status.state === "unavailable") {
        setPhase({ kind: "unavailable" });
        return;
      }
      if (status.state === "no_identity") {
        setPhase({ kind: "no_identity" });
        return;
      }
      if (!status.attested) {
        setPhase({ kind: "unrecognized", message: UNRECOGNIZED_BUILD_COPY });
        return;
      }
      setPhase({ kind: "ready" });
    } catch (error) {
      if (cancelledRef.current) return;
      const code = errorCode(error);
      if (code === "not_attested") {
        setPhase({ kind: "unrecognized", message: UNRECOGNIZED_BUILD_COPY });
        return;
      }
      if (code === "no_identity") {
        setPhase({ kind: "no_identity" });
        return;
      }
      setPhase({ kind: "unavailable" });
    }
  }, []);

  React.useEffect(() => {
    void probeResolver();
  }, [probeResolver]);

  const showNames = React.useCallback(async () => {
    setNotice(null);
    setPhase({ kind: "listing" });
    try {
      const identities = await listDntlsIdentities();
      if (cancelledRef.current) return;
      if (identities.length === 0) {
        setPhase({ kind: "empty" });
        return;
      }
      const active = identities.find(
        (identity) => identity.active && canUseIdentity(identity),
      );
      setPhase({
        kind: "list",
        identities,
        selectedName:
          active?.name ?? identities.find(canUseIdentity)?.name ?? null,
      });
    } catch (error) {
      if (cancelledRef.current) return;
      const code = errorCode(error);
      if (code === "denied") {
        setNotice(DENIED_COPY);
        setPhase({ kind: "ready" });
        return;
      }
      if (code === "unverified") {
        setPhase({ kind: "unrecognized", message: UNRECOGNIZED_COPY });
        return;
      }
      if (code === "not_attested") {
        setPhase({ kind: "unrecognized", message: UNRECOGNIZED_BUILD_COPY });
        return;
      }
      if (code === "no_identity") {
        setPhase({ kind: "no_identity" });
        return;
      }
      if (code === "resolver_unavailable") {
        setPhase({ kind: "unavailable" });
        return;
      }
      setNotice(errorMessage(error));
      setPhase({ kind: "ready" });
    }
  }, []);

  const useSelectedName = React.useCallback(
    async (identities: DntlsIdentity[], selectedName: string) => {
      const selected = identities.find(
        (identity) => identity.name === selectedName,
      );
      if (!selected || !canUseIdentity(selected)) return;
      setNotice(null);
      setPhase({ kind: "binding", identities, selectedName });
      try {
        const bound = await bindDntlsIdentity(selected.name);
        if (cancelledRef.current) return;
        setPhase({
          kind: "bound",
          bound,
          selectedFqdn: selected.fqdn,
        });
        onBound(bound.name);
      } catch (error) {
        if (cancelledRef.current) return;
        const code = errorCode(error);
        if (code === "denied") {
          setNotice(DENIED_COPY);
          setPhase({ kind: "list", identities, selectedName });
          return;
        }
        if (code === "unverified") {
          setPhase({ kind: "unrecognized", message: UNRECOGNIZED_COPY });
          return;
        }
        if (code === "not_attested") {
          setPhase({ kind: "unrecognized", message: UNRECOGNIZED_BUILD_COPY });
          return;
        }
        if (code === "resolver_unavailable") {
          setPhase({ kind: "unavailable" });
          return;
        }
        if (code === "no_identity") {
          setPhase({ kind: "no_identity" });
          return;
        }
        setNotice(errorMessage(error));
        setPhase({ kind: "list", identities, selectedName });
      }
    },
    [onBound],
  );

  const skipButton =
    onSkip && phase.kind !== "probing" && phase.kind !== "bound" ? (
      <Button
        className="rounded-full"
        data-testid="dntls-identity-picker-skip"
        onClick={onSkip}
        type="button"
        variant="ghost"
      >
        Skip for now
      </Button>
    ) : null;

  const cancelButton = onCancel ? (
    <Button
      className="rounded-full"
      data-testid="dntls-identity-picker-cancel"
      onClick={onCancel}
      type="button"
      variant="ghost"
    >
      Cancel
    </Button>
  ) : null;

  return (
    <div className="flex w-full flex-col gap-4" data-testid="dntls-identity-picker">
      {phase.kind === "probing" ? (
        <div className="flex justify-center py-6">
          <Spinner aria-label="Checking the Local Trust Resolver" />
        </div>
      ) : null}

      {phase.kind === "unavailable" ? (
        <StatusBlock
          message={UNAVAILABLE_COPY}
          onRetry={() => void probeResolver()}
        >
          <Button
            className="rounded-full px-0 text-sm"
            data-testid="dntls-identity-picker-downloads"
            onClick={() => void openUrl(RESOLVER_DOWNLOADS_URL)}
            type="button"
            variant="link"
          >
            {RESOLVER_DOWNLOADS_URL}
          </Button>
        </StatusBlock>
      ) : null}

      {phase.kind === "no_identity" ? (
        <StatusBlock
          message={NO_IDENTITY_COPY}
          onRetry={() => void probeResolver()}
        />
      ) : null}

      {phase.kind === "unrecognized" ? (
        <p className="text-sm leading-6 text-foreground">{phase.message}</p>
      ) : null}

      {phase.kind === "ready" || phase.kind === "listing" ? (
        <div className="flex flex-col items-start gap-3">
          {notice ? (
            <p className="text-sm leading-6 text-foreground">{notice}</p>
          ) : (
            <p className="text-sm leading-6 text-muted-foreground">
              {LIST_CONSENT_COPY}
            </p>
          )}
          <Button
            className="rounded-full"
            data-testid="dntls-identity-picker-show-names"
            disabled={phase.kind === "listing"}
            onClick={() => void showNames()}
            type="button"
          >
            {phase.kind === "listing" ? (
              <>
                <Spinner aria-hidden className="h-4 w-4 border-2" />
                Waiting for the Local Trust Resolver…
              </>
            ) : (
              "Show my names"
            )}
          </Button>
        </div>
      ) : null}

      {phase.kind === "empty" ? (
        <div className="flex flex-col items-start gap-3">
          <p className="text-sm leading-6 text-foreground">{EMPTY_COPY}</p>
          <p className="text-sm leading-6 text-muted-foreground">
            {NO_IDENTITY_COPY}
          </p>
          <Button
            className="rounded-full"
            data-testid="dntls-identity-picker-retry"
            onClick={() => void probeResolver()}
            type="button"
            variant="secondary"
          >
            Retry
          </Button>
        </div>
      ) : null}

      {phase.kind === "list" || phase.kind === "binding" ? (
        <div className="flex flex-col gap-3">
          {notice ? (
            <p className="text-sm leading-6 text-foreground">{notice}</p>
          ) : (
            <p className="text-sm leading-6 text-muted-foreground">
              {BIND_CONSENT_COPY}
            </p>
          )}
          <ul className="divide-y divide-border/55 overflow-hidden rounded-xl border border-border/70 bg-background/70">
            {phase.identities.map((identity) => {
              const usable = canUseIdentity(identity);
              const selected = phase.selectedName === identity.name;
              return (
                <li key={identity.name}>
                  <button
                    aria-pressed={selected}
                    className={cn(
                      "flex w-full items-center justify-between gap-3 px-4 py-3 text-left text-sm transition-colors",
                      usable
                        ? "hover:bg-muted/60"
                        : "cursor-not-allowed opacity-50",
                      selected && usable && "bg-muted/40",
                    )}
                    data-testid={`dntls-identity-picker-name-${identity.fqdn}`}
                    disabled={!usable || phase.kind === "binding"}
                    onClick={() => {
                      if (phase.kind !== "list") return;
                      setPhase({
                        kind: "list",
                        identities: phase.identities,
                        selectedName: identity.name,
                      });
                    }}
                    type="button"
                  >
                    <span className="min-w-0 truncate font-medium">
                      {identity.fqdn}
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {!usable
                        ? "No key on this machine"
                        : identity.active
                          ? "Active"
                          : null}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
          <Button
            className="rounded-full self-start"
            data-testid="dntls-identity-picker-use-name"
            disabled={
              phase.kind === "binding" ||
              phase.selectedName == null ||
              !phase.identities.some(
                (identity) =>
                  identity.name === phase.selectedName &&
                  canUseIdentity(identity),
              )
            }
            onClick={() => {
              if (phase.kind === "list" && phase.selectedName) {
                void useSelectedName(phase.identities, phase.selectedName);
              }
            }}
            type="button"
          >
            {phase.kind === "binding" ? (
              <>
                <Spinner aria-hidden className="h-4 w-4 border-2" />
                Waiting for the Local Trust Resolver…
              </>
            ) : (
              "Use this name"
            )}
          </Button>
        </div>
      ) : null}

      {phase.kind === "bound" ? (
        <div
          className="flex flex-col gap-1 text-sm leading-6 text-foreground"
          data-testid="dntls-identity-picker-bound"
        >
          <p>Buzz is bound as {phase.bound.name}</p>
          {phase.bound.scope === "subname" ? (
            <p className="text-muted-foreground">
              a Buzz-only subname of {phase.selectedFqdn}
            </p>
          ) : null}
        </div>
      ) : null}

      {skipButton || cancelButton ? (
        <div className="flex flex-wrap items-center gap-2">
          {skipButton}
          {cancelButton}
        </div>
      ) : null}
    </div>
  );
}

function StatusBlock({
  children,
  message,
  onRetry,
}: {
  children?: React.ReactNode;
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="flex flex-col items-start gap-3">
      <p className="text-sm leading-6 text-foreground">{message}</p>
      {children}
      <Button
        className="rounded-full"
        data-testid="dntls-identity-picker-retry"
        onClick={onRetry}
        type="button"
        variant="secondary"
      >
        Retry
      </Button>
    </div>
  );
}

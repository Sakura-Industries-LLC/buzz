import * as React from "react";

import {
  DNTLS_CREDENTIALS_CHANGED_MESSAGE,
  isDntlsError,
  redeemDntlsCredentialCode,
} from "@/features/communities/dntlsConnector";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

export const DNTLS_CONNECT_TITLE = "Connect your DNTLS name";
export const DNTLS_CODE_INSTRUCTION =
  "Paste the one-time code from your name's page in the DNTLS Portal (EXPORT → Export one-time code).";
export const DNTLS_CODE_INVALID_COPY =
  "That code is not valid. Codes work once and expire; export a new one.";
export const DNTLS_CODE_RATE_LIMITED_COPY = "Too many attempts, wait a minute.";
export const DNTLS_CREDENTIALS_CHANGED_COPY = DNTLS_CREDENTIALS_CHANGED_MESSAGE;
export const DNTLS_CODE_UNAVAILABLE_COPY =
  "Couldn't reach the DNTLS Portal. Try again.";

type FormProps = {
  initialNotice?: string | null;
  onCancel?: () => void;
  onConnected: (name: string) => void;
  onSkip?: () => void;
};

const REDEEM_ERROR_COPY: Record<string, string> = {
  credential_code_invalid: DNTLS_CODE_INVALID_COPY,
  rate_limited: DNTLS_CODE_RATE_LIMITED_COPY,
  credentials_changed: DNTLS_CREDENTIALS_CHANGED_COPY,
};

export function DntlsCredentialCodeForm({
  initialNotice = null,
  onCancel,
  onConnected,
  onSkip,
}: FormProps) {
  const inputId = React.useId();
  const [code, setCode] = React.useState("");
  const [error, setError] = React.useState<string | null>(initialNotice);
  const [busy, setBusy] = React.useState(false);
  const [connectedName, setConnectedName] = React.useState<string | null>(null);
  const cancelledRef = React.useRef(false);

  React.useEffect(() => {
    cancelledRef.current = false;
    return () => {
      cancelledRef.current = true;
    };
  }, []);

  React.useEffect(() => {
    setError(initialNotice ?? null);
  }, [initialNotice]);

  const trimmed = code.trim();

  async function handleConnect() {
    if (trimmed.length === 0 || busy) return;
    setBusy(true);
    setError(null);
    try {
      const redeemed = await redeemDntlsCredentialCode(trimmed);
      if (cancelledRef.current) return;
      setConnectedName(redeemed.name);
      setCode("");
    } catch (cause) {
      if (cancelledRef.current) return;
      setError(
        (isDntlsError(cause) && REDEEM_ERROR_COPY[cause.code]) ||
          DNTLS_CODE_UNAVAILABLE_COPY,
      );
    } finally {
      if (!cancelledRef.current) setBusy(false);
    }
  }

  if (connectedName != null) {
    return (
      <div
        className="flex w-full flex-col gap-4"
        data-testid="dntls-credential-code-form"
      >
        <div
          className="flex flex-col gap-3 text-sm leading-6 text-foreground"
          data-testid="dntls-credential-code-bound"
        >
          <p>Buzz is connected as {connectedName}</p>
          <Button
            className="w-fit rounded-full"
            data-testid="dntls-credential-code-continue"
            onClick={() => onConnected(connectedName)}
            type="button"
          >
            Continue
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="flex w-full flex-col gap-4"
      data-testid="dntls-credential-code-form"
    >
      <p className="text-sm leading-6 text-muted-foreground">
        {DNTLS_CODE_INSTRUCTION}
      </p>
      <form
        className="flex w-full flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          void handleConnect();
        }}
      >
        <label className="flex flex-col gap-1.5 text-left" htmlFor={inputId}>
          <span className="sr-only">One-time code</span>
          <Input
            autoCapitalize="none"
            autoComplete="off"
            autoCorrect="off"
            className="h-10 bg-background font-mono tracking-wide"
            data-testid="dntls-credential-code-input"
            id={inputId}
            disabled={busy}
            onChange={(event) => {
              setCode(event.target.value);
              if (error) setError(null);
            }}
            placeholder="XXXX-XXXX-XXXX"
            spellCheck={false}
            type="text"
            value={code}
          />
        </label>
        {error ? (
          <p
            className="text-sm leading-6 text-destructive"
            data-testid="dntls-credential-code-error"
          >
            {error}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            className="rounded-full"
            data-testid="dntls-credential-code-connect"
            disabled={busy || trimmed.length === 0}
            type="submit"
          >
            {busy ? (
              <>
                <Spinner aria-hidden className="h-4 w-4 border-2" />
                Connecting…
              </>
            ) : (
              "Connect"
            )}
          </Button>
          {onSkip ? (
            <Button
              className="rounded-full"
              data-testid="dntls-credential-code-skip"
              disabled={busy}
              onClick={onSkip}
              type="button"
              variant="ghost"
            >
              Skip for now
            </Button>
          ) : null}
          {onCancel ? (
            <Button
              className="rounded-full"
              data-testid="dntls-credential-code-cancel"
              disabled={busy}
              onClick={onCancel}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
          ) : null}
        </div>
      </form>
    </div>
  );
}

export function DntlsCredentialCodeDialog({
  initialNotice = null,
  onConnected,
  onOpenChange,
  open,
}: {
  initialNotice?: string | null;
  onConnected: (name: string) => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
}) {
  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent
        className="max-w-lg"
        data-testid="dntls-credential-code-dialog"
      >
        <DialogTitle>{DNTLS_CONNECT_TITLE}</DialogTitle>
        <DialogDescription className="sr-only">
          {DNTLS_CODE_INSTRUCTION}
        </DialogDescription>
        <DntlsCredentialCodeForm
          initialNotice={initialNotice}
          onCancel={() => onOpenChange(false)}
          onConnected={onConnected}
        />
      </DialogContent>
    </Dialog>
  );
}

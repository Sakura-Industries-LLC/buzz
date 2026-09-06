import * as React from "react";

import {
  dntlsCredentialsStatus,
  removeDntlsCredentials,
  type DntlsCredentialsStatus,
} from "@/features/communities/dntlsConnector";
import { DntlsIdentityPicker } from "@/features/communities/ui/DntlsIdentityPicker";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/shared/ui/dialog";

function formatStatus(status: DntlsCredentialsStatus | null): string {
  if (!status?.name) return "not set";
  return status.name;
}

export function DntlsIdentityRow() {
  const [status, setStatus] = React.useState<DntlsCredentialsStatus | null>(
    null,
  );
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [pickerOpen, setPickerOpen] = React.useState(false);
  const [reconnectHint, setReconnectHint] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    void dntlsCredentialsStatus()
      .then((next) => {
        if (!cancelled) setStatus(next);
      })
      .catch((loadError) => {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Could not read DNTLS credentials.",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleRemove() {
    setBusy(true);
    setError(null);
    setReconnectHint(false);
    try {
      await removeDntlsCredentials();
      setStatus({ name: null });
    } catch (removeError) {
      setError(
        removeError instanceof Error
          ? removeError.message
          : "Could not remove DNTLS credentials.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="px-4 py-3" data-testid="profile-dntls-identity-row">
      <div className="flex items-center justify-between gap-4">
        <p className="min-w-0 text-sm font-medium">
          DNTLS identity: {formatStatus(status)}
        </p>
        <div className="flex shrink-0 items-center gap-2">
          <Button
            className="rounded-full"
            data-testid="profile-dntls-identity-replace"
            disabled={busy}
            onClick={() => {
              setError(null);
              setPickerOpen(true);
            }}
            type="button"
            variant="secondary"
          >
            Replace
          </Button>
          {status?.name ? (
            <Button
              className="rounded-full"
              data-testid="profile-dntls-identity-remove"
              disabled={busy}
              onClick={() => void handleRemove()}
              type="button"
              variant="secondary"
            >
              Remove
            </Button>
          ) : null}
        </div>
      </div>
      {reconnectHint ? (
        <p className="mt-2 text-sm text-muted-foreground">
          DNTLS communities reconnect with this name the next time you launch
          Buzz.
        </p>
      ) : null}
      {error ? <p className="mt-2 text-sm text-destructive">{error}</p> : null}
      <Dialog
        onOpenChange={(open) => {
          if (!open) setPickerOpen(false);
        }}
        open={pickerOpen}
      >
        <DialogContent
          className="max-w-lg"
          data-testid="dntls-identity-picker-dialog"
        >
          <DialogTitle>Choose your DNTLS name</DialogTitle>
          <DialogDescription>
            Buzz will use this name when you join DNTLS communities.
          </DialogDescription>
          <DntlsIdentityPicker
            onBound={(name) => {
              setStatus({ name });
              setReconnectHint(true);
              setPickerOpen(false);
            }}
            onCancel={() => setPickerOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

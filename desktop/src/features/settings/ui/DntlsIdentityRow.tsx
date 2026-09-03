import * as React from "react";

import {
  dntlsCredentialsStatus,
  importDntlsCredentials,
  removeDntlsCredentials,
  type DntlsCredentialsStatus,
} from "@/features/communities/dntlsConnector";
import { Button } from "@/shared/ui/button";

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

  async function handleReplace() {
    setBusy(true);
    setError(null);
    try {
      const imported = await importDntlsCredentials();
      if (imported) setStatus(imported);
    } catch (replaceError) {
      setError(
        replaceError instanceof Error
          ? replaceError.message
          : "Could not replace DNTLS credentials.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove() {
    setBusy(true);
    setError(null);
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
            onClick={() => void handleReplace()}
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
      {error ? (
        <p className="mt-2 text-sm text-destructive">{error}</p>
      ) : null}
    </div>
  );
}

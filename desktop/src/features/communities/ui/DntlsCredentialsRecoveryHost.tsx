import * as React from "react";
import { listen } from "@tauri-apps/api/event";

import {
  DNTLS_CREDENTIALS_CHANGED_EVENT,
  subscribeDntlsCredentialsRecovery,
} from "@/features/communities/dntlsConnector";
import {
  DNTLS_CREDENTIALS_CHANGED_COPY,
  DntlsCredentialCodeDialog,
} from "@/features/communities/ui/DntlsCredentialCodeForm";
import { useCommunities } from "@/features/communities/useCommunities";

/**
 * Routes native credential rotation and connector-start failures for existing
 * communities onto the shared one-time-code form. Retry happens only after
 * a successful redeem so a stale connector URL is never reused.
 */
export function DntlsCredentialsRecoveryHost() {
  const { retryDntlsConnectors } = useCommunities();
  const [open, setOpen] = React.useState(false);
  const retryingRef = React.useRef(false);
  const recoveryPendingRef = React.useRef(false);

  const openRecovery = React.useCallback(() => {
    if (retryingRef.current) {
      recoveryPendingRef.current = true;
      return;
    }
    setOpen(true);
  }, []);

  React.useEffect(
    () => subscribeDntlsCredentialsRecovery(openRecovery),
    [openRecovery],
  );

  React.useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen(DNTLS_CREDENTIALS_CHANGED_EVENT, () => {
      if (!disposed) openRecovery();
    })
      .then((next) => {
        if (disposed) {
          next();
          return;
        }
        unlisten = next;
      })
      .catch(() => {
        // Event bridge is absent in unit tests and non-native shells.
      });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [openRecovery]);

  return (
    <DntlsCredentialCodeDialog
      initialNotice={open ? DNTLS_CREDENTIALS_CHANGED_COPY : null}
      onConnected={() => {
        setOpen(false);
        retryingRef.current = true;
        void retryDntlsConnectors()
          .then((needsRecovery) => {
            if (needsRecovery) setOpen(true);
          })
          .finally(() => {
            retryingRef.current = false;
            if (recoveryPendingRef.current) {
              recoveryPendingRef.current = false;
              setOpen(true);
            }
          });
      }}
      onOpenChange={setOpen}
      open={open}
    />
  );
}

/** Error normalized from a rejected Tauri invocation with its wire payload. */
export class TauriInvokeError extends Error {
  readonly payload: unknown;

  constructor(message: string, payload: unknown) {
    super(message);
    this.name = "TauriInvokeError";
    this.payload = payload;
  }
}

export function toTauriError(error: unknown): Error {
  if (error instanceof Error) return error;
  if (typeof error === "string") return new TauriInvokeError(error, error);
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return new TauriInvokeError(error.message, error);
  }
  try {
    return new TauriInvokeError(JSON.stringify(error), error);
  } catch {
    return new TauriInvokeError("Unknown Tauri error", error);
  }
}

const listeners = new Set<(error: Error) => void>();

/** Observe failures while a flow owns the active community. */
export function subscribeToTauriErrors(listener: (error: Error) => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Capture request ownership; unsubscribed flows never receive late failures. */
export function captureTauriErrorObservers() {
  if (!listeners.size) return undefined;
  const owners = Array.from(listeners);
  return (error: Error) => {
    for (const owner of owners) {
      if (listeners.has(owner)) owner(error);
    }
  };
}

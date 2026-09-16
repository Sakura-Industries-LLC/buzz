type CredentialRequest = {
  id: number;
  community: string;
  submit: (code: string) => Promise<void>;
  cancel: () => void;
};

let requests: readonly CredentialRequest[] = [];
let nextRequestId = 0;
const listeners = new Set<() => void>();

function changed() {
  for (const listener of listeners) listener();
}

export function subscribeAgentCode(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function currentAgentCodeRequest() {
  return requests[0] ?? null;
}

function remove(request: CredentialRequest) {
  requests = requests.filter((item) => item !== request);
  changed();
}

/** Holds creation until the person supplies credentials; failures stay inline. */
export function withAgentDntlsCode<T>(
  community: string,
  submit: (code: string) => Promise<T>,
): Promise<T> {
  // The desktop WebView targets ES2022, which has no Promise.withResolvers.
  return new Promise<T>((resolve, reject) => {
    const request: CredentialRequest = {
      id: nextRequestId++,
      community,
      async submit(code) {
        const result = await submit(code);
        remove(request);
        resolve(result);
      },
      cancel() {
        remove(request);
        reject(new Error("Agent creation cancelled."));
      },
    };
    requests = [...requests, request];
    changed();
  });
}

export function cancelAgentCodeRequests() {
  for (const request of requests) request.cancel();
}

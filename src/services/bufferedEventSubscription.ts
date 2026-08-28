import type { UnlistenFn } from "@tauri-apps/api/event";

type Settled<T> =
  | { ok: true; value: T }
  | { ok: false; error: unknown };

const settle = async <T,>(operation: () => Promise<T>): Promise<Settled<T>> => {
  try {
    return { ok: true, value: await operation() };
  } catch (error) {
    return { ok: false, error };
  }
};

interface BufferedEventSubscriptionOptions<EventName extends string, Payload, Context, Value> {
  eventNames: readonly EventName[];
  loadContext: () => Promise<Context>;
  listen: (eventName: EventName, handler: (payload: Payload) => void) => Promise<UnlistenFn>;
  adapt: (payload: Payload, context: Context) => Value;
  handle: (value: Value, eventName: EventName) => void;
}

interface SubscriptionReconciliationOptions {
  subscriptions: readonly (() => Promise<UnlistenFn>)[];
  reconcile: () => Promise<void>;
}

export interface SubscriptionReconciliation {
  close: UnlistenFn;
  ready: Promise<void>;
}

/**
 * Starts every native registration together, exposes synchronous cleanup, and
 * performs one startup reconciliation only after every operating-system
 * listener exists. Registrations that resolve after cleanup immediately
 * unlisten themselves, including the partial-registration failure path.
 */
export function subscribeAllThenReconcile(
  options: SubscriptionReconciliationOptions,
): SubscriptionReconciliation {
  let closed = false;
  const unlisteners: UnlistenFn[] = [];
  const close = () => {
    if (closed) return;
    closed = true;
    unlisteners.splice(0).forEach((unlisten) => unlisten());
  };

  const registrations = options.subscriptions.map(async (subscribe) => {
    const unlisten = await subscribe();
    if (closed) unlisten();
    else unlisteners.push(unlisten);
  });
  const ready = Promise.all(registrations)
    .then(async () => {
      if (!closed) await options.reconcile();
    })
    .catch((error: unknown) => {
      close();
      throw error;
    });

  return { close, ready };
}

/**
 * Registers every listener concurrently and buffers events until the context
 * required to adapt them is ready. Callers should still reconcile from their
 * authoritative store after this promise resolves: events emitted before an
 * operating-system listener existed cannot be replayed by the event bus.
 */
export async function subscribeBufferedEvents<EventName extends string, Payload, Context, Value>(
  options: BufferedEventSubscriptionOptions<EventName, Payload, Context, Value>,
): Promise<UnlistenFn> {
  let closed = false;
  let contextReady = false;
  let context: Context;
  const buffered: Array<{ eventName: EventName; payload: Payload }> = [];

  const registrationResultsPromise = Promise.all(options.eventNames.map((eventName) =>
    settle(() => options.listen(eventName, (payload) => {
      if (closed) return;
      if (!contextReady) {
        buffered.push({ eventName, payload });
        return;
      }
      options.handle(options.adapt(payload, context), eventName);
    })),
  ));
  const contextResultPromise = settle(options.loadContext);
  const [registrationResults, contextResult] = await Promise.all([
    registrationResultsPromise,
    contextResultPromise,
  ]);
  const unlisteners = registrationResults.flatMap((result) => result.ok ? [result.value] : []);
  const close = () => {
    if (closed) return;
    closed = true;
    buffered.length = 0;
    unlisteners.forEach((unlisten) => unlisten());
  };
  const registrationFailure = registrationResults.find((result) => !result.ok);

  if (!contextResult.ok || registrationFailure) {
    close();
    throw !contextResult.ok ? contextResult.error : registrationFailure?.error;
  }

  context = contextResult.value;
  contextReady = true;
  try {
    for (const event of buffered.splice(0)) {
      options.handle(options.adapt(event.payload, context), event.eventName);
    }
  } catch (error) {
    close();
    throw error;
  }

  return close;
}

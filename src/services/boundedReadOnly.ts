export type BoundedPromiseObservation<T> =
  | { outcome: "completed"; value: T }
  | { outcome: "failed"; error: unknown }
  | { outcome: "timed_out" };

/**
 * Bounds how long the UI waits for a promise without cancelling or inventing a
 * result for the underlying operation. This is also safe for a mutating IPC
 * when timeout is treated as an unknown outcome and followed by an
 * authoritative read. A late completion is deliberately observed and ignored.
 */
export const observePromiseWithin = <T>(
  read: Promise<T>,
  timeoutMs: number,
): Promise<BoundedPromiseObservation<T>> => new Promise((resolve) => {
  let settled = false;
  const finish = (result: BoundedPromiseObservation<T>) => {
    if (settled) return;
    settled = true;
    globalThis.clearTimeout(timer);
    resolve(result);
  };
  const timer = globalThis.setTimeout(() => finish({ outcome: "timed_out" }), timeoutMs);

  void read.then(
    (value) => finish({ outcome: "completed", value }),
    (error: unknown) => finish({ outcome: "failed", error }),
  );
});

export const settleReadOnlyWithin = observePromiseWithin;

export interface InFlightReadCoalescer<Key, Value> {
  read: (key: Key, start: () => Promise<Value>) => Promise<Value>;
}

/** Keeps one uncancelled authoritative read per identity until it settles. */
export const createInFlightReadCoalescer = <Key, Value>(): InFlightReadCoalescer<Key, Value> => {
  const inFlight = new Map<Key, Promise<Value>>();

  return {
    read(key, start) {
      const existing = inFlight.get(key);
      if (existing) return existing;

      let read: Promise<Value>;
      try {
        read = start();
      } catch (error) {
        read = Promise.reject(error);
      }
      inFlight.set(key, read);
      const release = () => {
        if (inFlight.get(key) === read) inFlight.delete(key);
      };
      void read.then(release, release);
      return read;
    },
  };
};

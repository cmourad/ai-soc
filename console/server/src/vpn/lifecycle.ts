/**
 * Serializes tunnel mutations inside one console process. Polling is allowed to
 * skip a turn instead of accumulating behind a slow wg-quick invocation.
 */
export class VpnOperationGate {
  private tail: Promise<void> = Promise.resolve();
  private active = 0;

  get busy(): boolean {
    return this.active > 0;
  }

  run<T>(operation: () => Promise<T>): Promise<T> {
    this.active += 1;
    const result = this.tail.then(operation, operation);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    void result
      .finally(() => {
        this.active -= 1;
      })
      .catch(() => undefined);
    return result;
  }
}

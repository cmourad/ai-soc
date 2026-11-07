import type { ServerMessage } from "@aisoc/shared";

/**
 * One fan-out point for everything the console pushes to connected clients.
 *
 * It lives on its own so that a module holding state can announce a change
 * without knowing who listens, and so that two state modules can both publish
 * without importing each other. Delivery is synchronous and unordered by
 * design: a subscriber that needs to do work off the back of a message queues
 * it itself rather than blocking the producer.
 */
type Subscriber = (message: ServerMessage) => void;

const subscribers = new Set<Subscriber>();

export function subscribe(fn: Subscriber): () => void {
  subscribers.add(fn);
  return () => subscribers.delete(fn);
}

export function broadcast(message: ServerMessage): void {
  for (const fn of subscribers) fn(message);
}

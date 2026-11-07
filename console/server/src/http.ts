import { z } from "zod";

/**
 * One error string for every route.
 *
 * Validation failures name the offending field, because the console shows this
 * text verbatim and "invalid request" tells an operator nothing about which
 * setting they got wrong.
 */
export function describeError(error: unknown): string {
  if (error instanceof z.ZodError) {
    return error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
  }
  return error instanceof Error ? error.message : String(error);
}

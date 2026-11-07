import { randomUUID } from "node:crypto";
import { chmodSync, closeSync, fsyncSync, openSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

/** Durable private-file replacement: exclusive temp, fsync, rename, mode 0600. */
export function writePrivateAtomic(path: string, contents: string | Buffer): void {
  const temp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  const fd = openSync(temp, "wx", 0o600);
  try {
    writeFileSync(fd, contents);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(temp, 0o600);
  renameSync(temp, path);
  chmodSync(path, 0o600);
}

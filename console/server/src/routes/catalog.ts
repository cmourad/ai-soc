import { MITRE_TECHNIQUE_COUNT } from "@aisoc/shared";
import type { FastifyInstance } from "fastify";
import { broadcast } from "../bus.js";
import { defaultRulePacks } from "../detect/feeds.js";
import { RULE_COUNT } from "../detect/rules.js";
import { addAudit, listPlaybooks, listRulePacks, setPlaybooks, setRulePacks } from "../store.js";

/** Detection rule packs and response playbooks. */
export function registerCatalogRoutes(app: FastifyInstance): void {
  // --- Rule packs -------------------------------------------------------------

  /**

   * Stands in for pulling fresh packs from a feed server. It re-stamps versions

   * and counts from what is actually loaded, so the view never claims a pack the

   * engine is not running.

   */

  app.post("/api/rulepacks/update", async (request) => {
    const packs = defaultRulePacks(RULE_COUNT, MITRE_TECHNIQUE_COUNT).map((pack) => ({
      ...pack,
      enabled: listRulePacks().find((existing) => existing.id === pack.id)?.enabled ?? pack.enabled,
      updatedAt: new Date().toISOString(),
    }));
    setRulePacks(packs);
    addAudit(request.actor, "rulepacks.update", "all", `Refreshed ${packs.length} packs.`);
    broadcast({
      type: "toast",
      level: "success",
      message: `Rule packs refreshed (${RULE_COUNT} rules).`,
    });
    return { ok: true, packs };
  });

  app.post<{ Params: { id: string } }>("/api/rulepacks/:id/toggle", async (request, reply) => {
    const packs = listRulePacks();
    const pack = packs.find((entry) => entry.id === request.params.id);
    if (!pack) return reply.code(404).send({ ok: false, error: "unknown pack" });
    pack.enabled = !pack.enabled;
    setRulePacks([...packs]);
    addAudit(request.actor, "rulepacks.toggle", pack.name, pack.enabled ? "enabled" : "disabled");
    return { ok: true, pack };
  });

  app.post<{ Params: { id: string } }>("/api/playbooks/:id/toggle", async (request, reply) => {
    const playbooks = listPlaybooks();
    const playbook = playbooks.find((entry) => entry.id === request.params.id);
    if (!playbook) return reply.code(404).send({ ok: false, error: "unknown playbook" });
    playbook.enabled = !playbook.enabled;
    setPlaybooks([...playbooks]);
    addAudit(
      request.actor,
      "playbook.toggle",
      playbook.name,
      playbook.enabled ? "enabled" : "disabled",
    );
    return { ok: true, playbook };
  });
}

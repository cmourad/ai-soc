import type { VpnServer } from "@aisoc/shared";

/**
 * Exit server catalogue.
 *
 * A real deployment fetches this from the provider's API; it is static here so
 * the picker works offline and the same exits are demonstrable every run. Load
 * figures move on their own (see `refreshLoad`) because a server list where
 * every exit sits at a fixed load tells an operator nothing.
 */
const CATALOGUE: Omit<VpnServer, "load" | "latencyMs">[] = [
  {
    id: "nl-ams-1",
    country: "Netherlands",
    countryCode: "NL",
    city: "Amsterdam",
    host: "nl-ams-1.vpn.internal",
    port: 51_820,
    publicKey: "K4xW9qPz2mN7vL0cR8tYbJ3fH6dS1gA5eU2iO9pQwX0=",
    lat: 52.3676,
    lon: 4.9041,
    tags: ["p2p", "low-latency"],
  },
  {
    id: "de-fra-1",
    country: "Germany",
    countryCode: "DE",
    city: "Frankfurt",
    host: "de-fra-1.vpn.internal",
    port: 51_820,
    publicKey: "R7bV2nM8xK1qW5zC9tE4yU0iP3aS6dF7gH2jL8oN1cY=",
    lat: 50.1109,
    lon: 8.6821,
    tags: ["low-latency", "streaming"],
  },
  {
    id: "fr-par-1",
    country: "France",
    countryCode: "FR",
    city: "Paris",
    host: "fr-par-1.vpn.internal",
    port: 51_820,
    publicKey: "M3zQ8wR1tY6uI9oP2aS5dF0gH7jK4lZ1xC6vB3nM9qW=",
    lat: 48.8566,
    lon: 2.3522,
    tags: ["streaming"],
  },
  {
    id: "gb-lon-1",
    country: "United Kingdom",
    countryCode: "GB",
    city: "London",
    host: "gb-lon-1.vpn.internal",
    port: 51_820,
    publicKey: "T5yU8iO1pA4sD7fG0hJ3kL6zX9cV2bN5mQ8wE1rT4yU=",
    lat: 51.5074,
    lon: -0.1278,
    tags: ["streaming", "low-latency"],
  },
  {
    id: "es-mad-1",
    country: "Spain",
    countryCode: "ES",
    city: "Madrid",
    host: "es-mad-1.vpn.internal",
    port: 51_820,
    publicKey: "B8nM2qW5eR9tY1uI4oP7aS0dF3gH6jK9lZ2xC5vB8nM=",
    lat: 40.4168,
    lon: -3.7038,
    tags: ["p2p"],
  },
  {
    id: "ch-zrh-1",
    country: "Switzerland",
    countryCode: "CH",
    city: "Zurich",
    host: "ch-zrh-1.vpn.internal",
    port: 51_820,
    publicKey: "C1vB4nM7qW0eR3tY6uI9oP2aS5dF8gH1jK4lZ7xC0vB=",
    lat: 47.3769,
    lon: 8.5417,
    tags: ["double-hop", "p2p"],
  },
  {
    id: "se-sto-1",
    country: "Sweden",
    countryCode: "SE",
    city: "Stockholm",
    host: "se-sto-1.vpn.internal",
    port: 51_820,
    publicKey: "V6bN9mQ2wE5rT8yU1iO4pA7sD0fG3hJ6kL9zX2cV5bN=",
    lat: 59.3293,
    lon: 18.0686,
    tags: ["p2p", "double-hop"],
  },
  {
    id: "us-nyc-1",
    country: "United States",
    countryCode: "US",
    city: "New York",
    host: "us-nyc-1.vpn.internal",
    port: 51_820,
    publicKey: "N4mQ7wE0rT3yU6iO9pA2sD5fG8hJ1kL4zX7cV0bN3mQ=",
    lat: 40.7128,
    lon: -74.006,
    tags: ["streaming"],
  },
  {
    id: "us-lax-1",
    country: "United States",
    countryCode: "US",
    city: "Los Angeles",
    host: "us-lax-1.vpn.internal",
    port: 51_820,
    publicKey: "Q9wE2rT5yU8iO1pA4sD7fG0hJ3kL6zX9cV2bN5mQ8w=",
    lat: 34.0522,
    lon: -118.2437,
    tags: ["streaming", "p2p"],
  },
  {
    id: "ca-tor-1",
    country: "Canada",
    countryCode: "CA",
    city: "Toronto",
    host: "ca-tor-1.vpn.internal",
    port: 51_820,
    publicKey: "W2eR5tY8uI1oP4aS7dF0gH3jK6lZ9xC2vB5nM8qW1eR=",
    lat: 43.6532,
    lon: -79.3832,
    tags: ["p2p"],
  },
  {
    id: "ma-cmn-1",
    country: "Morocco",
    countryCode: "MA",
    city: "Casablanca",
    host: "ma-cmn-1.vpn.internal",
    port: 51_820,
    publicKey: "E5rT8yU1iO4pA7sD0fG3hJ6kL9zX2cV5bN8mQ1wE4rT=",
    lat: 33.5731,
    lon: -7.5898,
    tags: ["low-latency"],
  },
  {
    id: "ae-dxb-1",
    country: "United Arab Emirates",
    countryCode: "AE",
    city: "Dubai",
    host: "ae-dxb-1.vpn.internal",
    port: 51_820,
    publicKey: "R8tY1uI4oP7aS0dF3gH6jK9lZ2xC5vB8nM1qW4eR7tY=",
    lat: 25.2048,
    lon: 55.2708,
    tags: ["obfuscated"],
  },
  {
    id: "sg-sin-1",
    country: "Singapore",
    countryCode: "SG",
    city: "Singapore",
    host: "sg-sin-1.vpn.internal",
    port: 51_820,
    publicKey: "T1uI4oP7aS0dF3gH6jK9lZ2xC5vB8nM1qW4eR7tY0uI=",
    lat: 1.3521,
    lon: 103.8198,
    tags: ["low-latency", "obfuscated"],
  },
  {
    id: "jp-tyo-1",
    country: "Japan",
    countryCode: "JP",
    city: "Tokyo",
    host: "jp-tyo-1.vpn.internal",
    port: 51_820,
    publicKey: "Y4uI7oP0aS3dF6gH9jK2lZ5xC8vB1nM4qW7eR0tY3uI=",
    lat: 35.6762,
    lon: 139.6503,
    tags: ["streaming", "low-latency"],
  },
  {
    id: "au-syd-1",
    country: "Australia",
    countryCode: "AU",
    city: "Sydney",
    host: "au-syd-1.vpn.internal",
    port: 51_820,
    publicKey: "U7iO0pA3sD6fG9hJ2kL5zX8cV1bN4mQ7wE0rT3yU6iO=",
    lat: -33.8688,
    lon: 151.2093,
    tags: ["p2p"],
  },
  {
    id: "br-sao-1",
    country: "Brazil",
    countryCode: "BR",
    city: "São Paulo",
    host: "br-sao-1.vpn.internal",
    port: 51_820,
    publicKey: "I0oP3aS6dF9gH2jK5lZ8xC1vB4nM7qW0eR3tY6uI9oP=",
    lat: -23.5505,
    lon: -46.6333,
    tags: ["streaming"],
  },
];

/**
 * Latency is modelled from great-circle distance to the site rather than made
 * up, so "nearest" and "fastest" agree with each other and the sort order stays
 * believable when the operator moves the site in settings.
 */
function distanceKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
}

const state = new Map<string, { load: number; latencyMs: number | null }>();

export function listServers(site: { lat: number; lon: number }): VpnServer[] {
  return CATALOGUE.map((server) => {
    let current = state.get(server.id);
    if (!current) {
      current = { load: 20 + Math.floor(Math.random() * 55), latencyMs: null };
      state.set(server.id, current);
    }
    // ~0.02 ms/km round trip through fibre, plus a floor for the handshake.
    const latency =
      current.latencyMs ?? Math.round(8 + distanceKm(site, server) * 0.02 + Math.random() * 6);
    current.latencyMs = latency;
    return { ...server, load: current.load, latencyMs: latency };
  });
}

export function getServer(id: string, site: { lat: number; lon: number }): VpnServer | undefined {
  return listServers(site).find((server) => server.id === id);
}

/** Nudges load figures so the picker reflects a live estate rather than a fixture. */
export function refreshLoad(): void {
  for (const [id, current] of state) {
    const drift = Math.round((Math.random() - 0.5) * 8);
    state.set(id, { ...current, load: Math.min(97, Math.max(4, current.load + drift)) });
  }
}

/**
 * The exit the client would pick on its own: lowest load among the quickest
 * third, optionally constrained to a country the operator prefers.
 */
export function recommendServer(
  site: { lat: number; lon: number },
  preferredCountry: string,
): VpnServer | undefined {
  const all = listServers(site);
  const pool = preferredCountry
    ? all.filter(
        (server) =>
          server.countryCode.toLowerCase() === preferredCountry.toLowerCase() ||
          server.country.toLowerCase() === preferredCountry.toLowerCase(),
      )
    : all;
  if (pool.length === 0) return undefined;

  const byLatency = [...pool].sort((a, b) => (a.latencyMs ?? 0) - (b.latencyMs ?? 0));
  const quickest = byLatency.slice(0, Math.max(1, Math.ceil(byLatency.length / 3)));
  return quickest.sort((a, b) => a.load - b.load)[0];
}

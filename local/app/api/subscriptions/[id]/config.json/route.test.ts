import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  consumeLocalRateLimit: vi.fn(),
  generateSubscriptionSingBoxJson: vi.fn(),
  getTrustedClientRateLimitKey: vi.fn(),
  hashLocalRateLimitKey: vi.fn(() => "token-hash"),
  localRateLimitResponse: vi.fn(
    () => new Response(JSON.stringify({ error: "limited", code: "RATE_LIMITED" }), { status: 429 })
  ),
}));

vi.mock("@local/lib/rate-limit", () => ({
  consumeLocalRateLimit: mocks.consumeLocalRateLimit,
  getTrustedClientRateLimitKey: mocks.getTrustedClientRateLimitKey,
  hashLocalRateLimitKey: mocks.hashLocalRateLimitKey,
  localRateLimitResponse: mocks.localRateLimitResponse,
}));
vi.mock("@local/lib/subscription-service", () => ({
  generateSubscriptionSingBoxJson: mocks.generateSubscriptionSingBoxJson,
}));

import { GET } from "./route";

describe("local sing-box subscription JSON route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.consumeLocalRateLimit.mockReturnValue({ allowed: true, retryAfterSeconds: 0 });
    mocks.getTrustedClientRateLimitKey.mockReturnValue("client-hash");
    mocks.generateSubscriptionSingBoxJson.mockResolvedValue({
      json: '{"outbounds":[]}\n',
      name: "Test",
      subscriptionInfo: {},
      cacheExpirySeconds: 3600,
      autoUpdateIntervalSeconds: null,
      isAdmin: true,
    });
  });

  it("returns JSON with the same subscription metadata and rate limits", async () => {
    const response = await GET(new Request("https://local.test/config.json"), {
      params: Promise.resolve({ id: "secret-token" }),
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json;charset=utf-8");
    expect(await response.text()).toBe('{"outbounds":[]}\n');
    expect(mocks.hashLocalRateLimitKey).toHaveBeenCalledWith("secret-token");
    expect(mocks.consumeLocalRateLimit).toHaveBeenNthCalledWith(
      1,
      "subscription-yaml-client",
      "client-hash",
      { limit: 600, windowMs: 60_000 }
    );
    expect(mocks.consumeLocalRateLimit).toHaveBeenNthCalledWith(
      2,
      "subscription-yaml-token",
      "token-hash",
      { limit: 120, windowMs: 60_000 }
    );
    expect(mocks.generateSubscriptionSingBoxJson).toHaveBeenCalledWith("secret-token");
  });

  it("returns 404 when the saved subscription has no materialized nodes", async () => {
    mocks.generateSubscriptionSingBoxJson.mockResolvedValueOnce(null);
    const response = await GET(new Request("https://local.test/config.json"), {
      params: Promise.resolve({ id: "provider-only" }),
    });
    expect(response.status).toBe(404);
  });

  it("returns 429 before touching subscription data", async () => {
    mocks.consumeLocalRateLimit.mockReturnValueOnce({ allowed: false, retryAfterSeconds: 17 });

    const response = await GET(new Request("https://local.test/config.json"), {
      params: Promise.resolve({ id: "secret-token" }),
    });

    expect(response.status).toBe(429);
    expect(mocks.localRateLimitResponse).toHaveBeenCalledWith(
      "Too many subscription requests. Try again later.",
      17
    );
    expect(mocks.generateSubscriptionSingBoxJson).not.toHaveBeenCalled();
  });
});

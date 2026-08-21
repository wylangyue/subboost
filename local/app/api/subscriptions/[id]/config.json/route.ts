import { apiError } from "@local/lib/http";
import { generateSubscriptionSingBoxJson } from "@local/lib/subscription-service";
import { buildSubscriptionResponseHeaders } from "@subboost/server-core/subscription";
import {
  consumeLocalRateLimit,
  getTrustedClientRateLimitKey,
  hashLocalRateLimitKey,
  localRateLimitResponse,
} from "@local/lib/rate-limit";

type RouteContext = {
  params: Promise<{ id: string }>;
};

export async function GET(request: Request, { params }: RouteContext) {
  const { id: token } = await params;
  const clientKey = getTrustedClientRateLimitKey(request);
  if (clientKey) {
    const clientLimit = consumeLocalRateLimit("subscription-yaml-client", clientKey, {
      limit: 600,
      windowMs: 60_000,
    });
    if (!clientLimit.allowed) {
      return localRateLimitResponse("Too many subscription requests. Try again later.", clientLimit.retryAfterSeconds);
    }
  }
  const tokenLimit = consumeLocalRateLimit("subscription-yaml-token", hashLocalRateLimitKey(token), {
    limit: 120,
    windowMs: 60_000,
  });
  if (!tokenLimit.allowed) {
    return localRateLimitResponse("Too many subscription requests. Try again later.", tokenLimit.retryAfterSeconds);
  }

  const result = await generateSubscriptionSingBoxJson(token);
  if (!result) return apiError("sing-box subscription config not found.", "NOT_FOUND", 404);

  return new Response(result.json, {
    headers: {
      ...buildSubscriptionResponseHeaders(result.name, result.subscriptionInfo, {
        cacheControl: "no-store",
        cacheExpirySeconds: result.cacheExpirySeconds,
        autoUpdateIntervalSeconds: result.autoUpdateIntervalSeconds,
        isAdmin: result.isAdmin,
      }),
      "content-type": "application/json;charset=utf-8",
    },
  });
}

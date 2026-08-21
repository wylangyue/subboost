import { generateClashConfig, type GenerateOptions } from "@subboost/core/generator";
import { isMihomoSupportedProxyNode, normalizeMihomoVlessForGeneration } from "@subboost/core/mihomo/proxy-sanitizer";
import type { ClashConfig, ProxyGroup, RuleProvider } from "@subboost/core/types/config";
import type { ParsedNode } from "@subboost/core/types/node";

export const SING_BOX_TARGET_VERSION = "1.13";

export type SingBoxConfig = Record<string, unknown>;

type RecordValue = Record<string, unknown>;

type ConvertedNode = {
  outbound?: RecordValue;
  endpoint?: RecordValue;
};

function isRecord(value: unknown): value is RecordValue {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function boolValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function stringArray(value: unknown): string[] | undefined {
  if (typeof value === "string") {
    const item = value.trim();
    return item ? [item] : undefined;
  }
  if (!Array.isArray(value)) return undefined;
  const out = value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);
  return out.length > 0 ? out : undefined;
}

function compact<T extends RecordValue>(record: T): T {
  return Object.fromEntries(
    Object.entries(record).filter(([, value]) => {
      if (value === undefined || value === null || value === "") return false;
      if (Array.isArray(value) && value.length === 0) return false;
      if (isRecord(value) && Object.keys(value).length === 0) return false;
      return true;
    })
  ) as T;
}

function secondsToDuration(value: unknown, fallback?: string): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return fallback;
    if (/^-?\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)$/.test(trimmed)) return trimmed;
    const numeric = Number(trimmed);
    return Number.isFinite(numeric) ? `${numeric}s` : fallback;
  }
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return `${value}s`;
  return fallback;
}

function normalizeHeaders(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === "string" && raw.trim()) {
      out[key] = raw;
    } else if (Array.isArray(raw)) {
      const joined = raw.filter((item): item is string => typeof item === "string").join(", ");
      if (joined) out[key] = joined;
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function convertTls(node: RecordValue, defaultEnabled = false): RecordValue | undefined {
  const reality = isRecord(node["reality-opts"]) ? node["reality-opts"] : undefined;
  const enabled = node.tls === true || Boolean(reality) || defaultEnabled;
  if (!enabled) return undefined;

  const fingerprint = stringValue(node["client-fingerprint"]);
  const supportedUtlsFingerprints = new Set([
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized",
  ]);
  const utlsFingerprint = fingerprint && supportedUtlsFingerprints.has(fingerprint.toLowerCase())
    ? fingerprint.toLowerCase()
    : undefined;

  const realityPublicKey = reality ? stringValue(reality["public-key"]) : undefined;
  const realityShortId = reality ? stringValue(reality["short-id"]) : undefined;

  return compact({
    enabled: true,
    server_name: stringValue(node.servername) ?? stringValue(node.sni),
    insecure: boolValue(node["skip-cert-verify"]),
    alpn: stringArray(node.alpn),
    utls: utlsFingerprint ? { enabled: true, fingerprint: utlsFingerprint } : undefined,
    reality: realityPublicKey
      ? compact({ enabled: true, public_key: realityPublicKey, short_id: realityShortId })
      : undefined,
  });
}

function convertTransport(node: RecordValue): RecordValue | undefined | null {
  const network = stringValue(node.network)?.toLowerCase();
  if (!network || network === "tcp") return undefined;
  if (network === "xhttp") return null;

  if (network === "ws") {
    const opts = isRecord(node["ws-opts"]) ? node["ws-opts"] : {};
    const path = stringValue(opts.path) ?? "/";
    const earlyData = /[?&]ed=(\d+)/.exec(path);
    const cleanPath = earlyData ? path.replace(/([?&])ed=\d+(&?)/, (_m, prefix: string, suffix: string) => suffix ? prefix : "").replace(/[?&]$/, "") : path;
    return compact({
      type: "ws",
      path: cleanPath || "/",
      headers: normalizeHeaders(opts.headers),
      max_early_data: earlyData ? Number.parseInt(earlyData[1], 10) : undefined,
      early_data_header_name: earlyData ? "Sec-WebSocket-Protocol" : undefined,
    });
  }

  if (network === "grpc") {
    const opts = isRecord(node["grpc-opts"]) ? node["grpc-opts"] : {};
    return compact({ type: "grpc", service_name: stringValue(opts["grpc-service-name"]) });
  }

  if (network === "http" || network === "h2") {
    const opts = isRecord(node[network === "h2" ? "h2-opts" : "http-opts"])
      ? node[network === "h2" ? "h2-opts" : "http-opts"] as RecordValue
      : {};
    const paths = stringArray(opts.path);
    return compact({
      type: "http",
      host: stringArray(opts.host),
      path: paths?.[0] ?? stringValue(opts.path),
      method: stringValue(opts.method),
      headers: normalizeHeaders(opts.headers),
    });
  }

  return null;
}

function convertPluginOptions(plugin: string, value: unknown): string | undefined {
  if (typeof value === "string") return value.trim() || undefined;
  if (!isRecord(value)) return undefined;

  if (plugin === "obfs-local") {
    const mode = stringValue(value.mode) ?? stringValue(value.obfs);
    const host = stringValue(value.host) ?? stringValue(value["obfs-host"]);
    return [mode ? `obfs=${mode}` : "", host ? `obfs-host=${host}` : ""].filter(Boolean).join(";") || undefined;
  }

  const parts: string[] = [];
  for (const [key, raw] of Object.entries(value)) {
    if (raw === undefined || raw === null || raw === "") continue;
    const normalizedKey = key.replace(/_/g, "-");
    if (raw === true) parts.push(normalizedKey);
    else if (raw === false) continue;
    else parts.push(`${normalizedKey}=${String(raw)}`);
  }
  return parts.join(";") || undefined;
}

function addDialFields(outbound: RecordValue, node: RecordValue): RecordValue {
  const detour = stringValue(node["dialer-proxy"]);
  return compact({
    ...outbound,
    detour,
    tcp_fast_open: boolValue(node.tfo),
  });
}

function parseServerPorts(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const values = value.map(String).map((item) => item.trim()).filter(Boolean);
    return values.length > 0 ? values : undefined;
  }
  const raw = stringValue(value);
  if (!raw) return undefined;
  const values = raw.split(",").map((item) => item.trim()).filter(Boolean);
  return values.length > 0 ? values : undefined;
}

function byteTriplet(value: unknown): number[] | undefined {
  const raw = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.replace(/^\[|\]$/g, "").split(",")
      : [];
  const bytes = raw.map((item) => Number.parseInt(String(item).trim(), 10));
  return bytes.length === 3 && bytes.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)
    ? bytes
    : undefined;
}

function normalizeCidrAddress(value: unknown, defaultPrefix: 32 | 128): string | undefined {
  const address = stringValue(value);
  if (!address) return undefined;
  return address.includes("/") ? address : `${address}/${defaultPrefix}`;
}

function convertWireGuardPeer(value: unknown, fallbackKeepalive?: number): RecordValue | null {
  if (!isRecord(value)) return null;
  const address = stringValue(value.address) ?? stringValue(value.server);
  const port = numberValue(value.port);
  const publicKey = stringValue(value.public_key) ?? stringValue(value["public-key"]);
  if (!address || !port || !publicKey) return null;

  return compact({
    address,
    port,
    public_key: publicKey,
    pre_shared_key: stringValue(value.pre_shared_key) ?? stringValue(value["pre-shared-key"]),
    allowed_ips: stringArray(value.allowed_ips) ?? stringArray(value["allowed-ips"]) ?? ["0.0.0.0/0", "::/0"],
    persistent_keepalive_interval: numberValue(value.persistent_keepalive_interval)
      ?? numberValue(value.keepalive)
      ?? fallbackKeepalive,
    reserved: byteTriplet(value.reserved),
  });
}

function convertWireGuard(node: RecordValue): ConvertedNode | null {
  const privateKey = stringValue(node["private-key"]);
  if (!privateKey) return null;

  const addresses = [
    normalizeCidrAddress(node.ip, 32),
    normalizeCidrAddress(node.ipv6, 128),
  ].filter((item): item is string => Boolean(item));
  if (addresses.length === 0) return null;

  const keepalive = numberValue(node.keepalive);
  const explicitPeers = Array.isArray(node.peers)
    ? node.peers.map((peer) => convertWireGuardPeer(peer, keepalive)).filter((peer): peer is RecordValue => Boolean(peer))
    : [];
  const legacyPeer = convertWireGuardPeer({
    server: node.server,
    port: node.port,
    "public-key": node["public-key"],
    "pre-shared-key": node["pre-shared-key"],
    "allowed-ips": node["allowed-ips"],
    reserved: node.reserved,
    keepalive,
  });
  const peers = explicitPeers.length > 0 ? explicitPeers : legacyPeer ? [legacyPeer] : [];
  if (peers.length === 0) return null;

  const endpoint = addDialFields(compact({
    type: "wireguard",
    tag: stringValue(node.name),
    mtu: numberValue(node.mtu),
    address: addresses,
    private_key: privateKey,
    peers,
  }), node);
  return { endpoint };
}

function convertNode(node: ParsedNode): ConvertedNode | null {
  const value = node as unknown as RecordValue;
  const tag = stringValue(value.name);
  const server = stringValue(value.server);
  const serverPort = numberValue(value.port);
  const type = stringValue(value.type);
  if (!tag || !type) return null;

  if (type === "wireguard") return convertWireGuard(value);
  if (!server || !serverPort) return null;

  const common = { tag, server, server_port: serverPort };

  if (type === "ss") {
    const method = stringValue(value.cipher);
    const password = stringValue(value.password);
    if (!method || !password) return null;
    const rawPlugin = stringValue(value.plugin);
    const plugin = rawPlugin === "obfs" ? "obfs-local" : rawPlugin;
    if (plugin && plugin !== "obfs-local" && plugin !== "v2ray-plugin") return null;
    return { outbound: addDialFields(compact({
      type: "shadowsocks",
      ...common,
      method,
      password,
      plugin,
      plugin_opts: plugin ? convertPluginOptions(plugin, value["plugin-opts"]) : undefined,
      udp_over_tcp: value["udp-over-tcp"] === true ? { enabled: true } : undefined,
    }), value) };
  }

  if (type === "vmess") {
    const uuid = stringValue(value.uuid);
    if (!uuid) return null;
    const transport = convertTransport(value);
    if (transport === null) return null;
    return { outbound: addDialFields(compact({
      type: "vmess",
      ...common,
      uuid,
      security: stringValue(value.cipher) ?? "auto",
      alter_id: numberValue(value.alterId) ?? 0,
      global_padding: boolValue(value["global-padding"]),
      authenticated_length: boolValue(value["authenticated-length"]),
      packet_encoding: stringValue(value["packet-encoding"]),
      tls: convertTls(value),
      transport,
    }), value) };
  }

  if (type === "vless") {
    const uuid = stringValue(value.uuid);
    if (!uuid) return null;
    const transport = convertTransport(value);
    if (transport === null) return null;
    return { outbound: addDialFields(compact({
      type: "vless",
      ...common,
      uuid,
      flow: stringValue(value.flow),
      packet_encoding: stringValue(value["packet-encoding"]),
      tls: convertTls(value),
      transport,
    }), value) };
  }

  if (type === "trojan") {
    const password = stringValue(value.password);
    if (!password) return null;
    const transport = convertTransport(value);
    if (transport === null) return null;
    return { outbound: addDialFields(compact({
      type: "trojan",
      ...common,
      password,
      tls: convertTls(value, true),
      transport,
    }), value) };
  }

  if (type === "anytls") {
    const password = stringValue(value.password);
    if (!password) return null;
    return { outbound: addDialFields(compact({
      type: "anytls",
      ...common,
      password,
      idle_session_check_interval: secondsToDuration(value["idle-session-check-interval"]),
      idle_session_timeout: secondsToDuration(value["idle-session-timeout"]),
      min_idle_session: numberValue(value["min-idle-session"]),
      tls: convertTls(value, true),
    }), value) };
  }

  if (type === "hysteria") {
    const authStr = stringValue(value["auth-str"]);
    const auth = stringValue(value.auth);
    const up = stringValue(value.up);
    const down = stringValue(value.down);
    if ((!authStr && !auth) || !up || !down) return null;
    const serverPorts = parseServerPorts(value.ports);
    return { outbound: addDialFields(compact({
      type: "hysteria",
      ...common,
      ...(serverPorts ? { server_port: undefined, server_ports: serverPorts } : {}),
      hop_interval: secondsToDuration(value["hop-interval"]),
      up,
      down,
      obfs: stringValue(value.obfs) ?? stringValue(value._obfs),
      auth,
      auth_str: authStr,
      tls: convertTls(value, true),
    }), value) };
  }

  if (type === "hysteria2") {
    const password = stringValue(value.password);
    if (!password) return null;
    const serverPorts = parseServerPorts(value.ports);
    const obfsType = stringValue(value.obfs);
    const obfsPassword = stringValue(value["obfs-password"]);
    return { outbound: addDialFields(compact({
      type: "hysteria2",
      ...common,
      ...(serverPorts ? { server_port: undefined, server_ports: serverPorts } : {}),
      hop_interval: secondsToDuration(value["hop-interval"]),
      up_mbps: numberValue(value.up),
      down_mbps: numberValue(value.down),
      password,
      obfs: obfsType && obfsPassword ? { type: obfsType, password: obfsPassword } : undefined,
      tls: convertTls(value, true),
    }), value) };
  }

  if (type === "tuic") {
    const uuid = stringValue(value.uuid);
    const password = stringValue(value.password) ?? stringValue(value.token);
    if (!uuid || !password) return null;
    return { outbound: addDialFields(compact({
      type: "tuic",
      ...common,
      uuid,
      password,
      congestion_control: stringValue(value["congestion-controller"]),
      udp_relay_mode: stringValue(value["udp-relay-mode"]),
      zero_rtt_handshake: boolValue(value["reduce-rtt"]),
      heartbeat: secondsToDuration(value["heartbeat-interval"]),
      tls: convertTls(value, true),
    }), value) };
  }

  if (type === "socks5" || type === "socks4") {
    return { outbound: addDialFields(compact({
      type: "socks",
      ...common,
      version: type === "socks4" ? "4" : "5",
      username: stringValue(value.username),
      password: stringValue(value.password),
    }), value) };
  }

  if (type === "http" || type === "https") {
    return { outbound: addDialFields(compact({
      type: "http",
      ...common,
      username: stringValue(value.username),
      password: stringValue(value.password),
      tls: type === "https" || value.tls === true ? convertTls({ ...value, tls: true }, true) : undefined,
    }), value) };
  }

  if (type === "ssh") {
    if (!stringValue(value.password) && !stringValue(value["private-key"])) return null;
    return { outbound: addDialFields(compact({
      type: "ssh",
      ...common,
      user: stringValue(value.username),
      password: stringValue(value.password),
      private_key: stringValue(value["private-key"]),
      private_key_passphrase: stringValue(value["private-key-passphrase"]),
      host_key: stringArray(value["host-key"]),
    }), value) };
  }

  return null;
}

function normalizeNodeForSingBoxCompatibility(node: ParsedNode): ParsedNode {
  const value = node as unknown as RecordValue;
  return value.type === "vless"
    ? normalizeMihomoVlessForGeneration(value) as unknown as ParsedNode
    : node;
}

export function isSingBoxCompatibleNode(node: ParsedNode): boolean {
  const normalized = normalizeNodeForSingBoxCompatibility(node);
  return isMihomoSupportedProxyNode(normalized) && Boolean(convertNode(normalized));
}

export function hasSingBoxCompatibleNodes(nodes: ParsedNode[]): boolean {
  return nodes.some(isSingBoxCompatibleNode);
}

function convertGroup(group: ProxyGroup, validTags: Set<string>, testUrl: string, testInterval: number): RecordValue | null {
  const tag = stringValue(group.name);
  if (!tag) return null;
  const members = (Array.isArray(group.proxies) ? group.proxies : [])
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter((item) => item && item !== tag && validTags.has(item));
  const deduplicated = [...new Set(members)];
  const safeMembers = deduplicated.length > 0 ? deduplicated : ["DIRECT"];

  if (group.type === "url-test" || group.type === "fallback") {
    return compact({
      type: "urltest",
      tag,
      outbounds: safeMembers,
      url: stringValue(group.url) ?? testUrl,
      interval: secondsToDuration(group.interval ?? testInterval, "5m"),
      tolerance: numberValue(group.tolerance),
    });
  }

  // sing-box has no native Clash load-balance group. Keep members selectable instead of
  // silently pretending URLTest is load balancing.
  return compact({ type: "selector", tag, outbounds: safeMembers });
}

function singBoxRuleSetUrl(provider: RuleProvider): string | undefined {
  const url = stringValue(provider.url);
  if (!url) return undefined;
  return url
    .replace(/\/raw\/refs\/heads\/meta\/geo\//, "/raw/refs/heads/sing/geo/")
    .replace(/\/raw\/meta\/geo\//, "/raw/sing/geo/")
    .replace(/\/meta\/geo\//, "/sing/geo/")
    .replace(/\.mrs(?=([?#]|$))/, ".srs");
}

function convertRuleSets(config: ClashConfig): RecordValue[] {
  const providers = isRecord(config["rule-providers"]) ? config["rule-providers"] as Record<string, RuleProvider> : {};
  const out: RecordValue[] = [];
  for (const [tag, provider] of Object.entries(providers)) {
    const url = singBoxRuleSetUrl(provider);
    if (!url) continue;
    out.push({
      type: "remote",
      tag,
      format: "binary",
      url,
      update_interval: secondsToDuration(provider.interval, "1d"),
    });
  }
  return out;
}

function ruleTargetAction(target: string): RecordValue {
  if (target === "REJECT") return { action: "reject" };
  return { action: "route", outbound: target };
}

function parsePortRule(value: string, field: "port" | "source_port"): RecordValue {
  if (/^\d+$/.test(value)) return { [field]: Number.parseInt(value, 10) };
  return { [field === "port" ? "port_range" : "source_port_range"]: value };
}

function addDynamicGeoRuleSet(
  kind: "geoip" | "geosite",
  value: string,
  ruleSets: RecordValue[],
  knownRuleSetTags: Set<string>
): string | null {
  const code = value.trim().toLowerCase();
  if (!code || !/^[a-z0-9_@!+.-]+$/.test(code)) return null;
  const tag = `${kind}-${code}`;
  if (!knownRuleSetTags.has(tag)) {
    knownRuleSetTags.add(tag);
    ruleSets.push({
      type: "remote",
      tag,
      format: "binary",
      url: `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/${kind}/${code}.srs`,
      update_interval: "1d",
    });
  }
  return tag;
}

function convertRule(
  text: string,
  validPolicyTargets: Set<string>,
  ruleSets: RecordValue[],
  knownRuleSetTags: Set<string>
): { rule?: RecordValue; final?: string } {
  const parts = text.split(",");
  const type = (parts[0] ?? "").trim().toUpperCase();
  const value = (parts[1] ?? "").trim();
  const target = (parts[2] ?? "").trim();

  if (type === "MATCH") {
    const matchTarget = value;
    return validPolicyTargets.has(matchTarget) && matchTarget !== "REJECT"
      ? { final: matchTarget }
      : { rule: matchTarget === "REJECT" ? { action: "reject" } : undefined };
  }
  if (!target || (!validPolicyTargets.has(target) && target !== "REJECT")) return {};

  const action = ruleTargetAction(target);
  if (type === "RULE-SET") {
    if (!knownRuleSetTags.has(value)) return {};
    return { rule: { rule_set: value, ...action } };
  }
  if (type === "DOMAIN") return { rule: { domain: value, ...action } };
  if (type === "DOMAIN-SUFFIX") return { rule: { domain_suffix: value, ...action } };
  if (type === "DOMAIN-KEYWORD") return { rule: { domain_keyword: value, ...action } };
  if (type === "IP-CIDR" || type === "IP-CIDR6") return { rule: { ip_cidr: value, ...action } };
  if (type === "PROCESS-NAME") return { rule: { process_name: value, ...action } };
  if (type === "DST-PORT") return { rule: { ...parsePortRule(value, "port"), ...action } };
  if (type === "SRC-PORT") return { rule: { ...parsePortRule(value, "source_port"), ...action } };
  if (type === "GEOIP" || type === "GEOSITE") {
    const ruleSetTag = addDynamicGeoRuleSet(type === "GEOIP" ? "geoip" : "geosite", value, ruleSets, knownRuleSetTags);
    return ruleSetTag ? { rule: { rule_set: ruleSetTag, ...action } } : {};
  }
  return {};
}

function convertListeners(config: ClashConfig, mixedPort: number, allowLan: boolean): { inbounds: RecordValue[]; rules: RecordValue[] } {
  const listenAddress = allowLan ? "::" : "127.0.0.1";
  const inbounds: RecordValue[] = [{ type: "mixed", tag: "mixed-in", listen: listenAddress, listen_port: mixedPort }];
  const rules: RecordValue[] = [{ inbound: "mixed-in", action: "sniff" }];

  const listeners = Array.isArray(config.listeners) ? config.listeners : [];
  const usedPorts = new Set([mixedPort]);
  for (let index = 0; index < listeners.length; index += 1) {
    const listener = listeners[index];
    if (!isRecord(listener) || listener.type !== "mixed") continue;
    const port = numberValue(listener.port);
    const proxy = stringValue(listener.proxy);
    if (!port || !proxy || usedPorts.has(port)) continue;
    usedPorts.add(port);
    const tag = stringValue(listener.name) ?? `mixed-${index + 1}`;
    inbounds.push({
      type: "mixed",
      tag,
      listen: stringValue(listener.listen) ?? listenAddress,
      listen_port: port,
    });
    rules.push({ inbound: tag, action: "sniff" });
    rules.push({ inbound: tag, ...ruleTargetAction(proxy) });
  }
  return { inbounds, rules };
}

export function generateSingBoxConfig(options: GenerateOptions): SingBoxConfig {
  // Reuse SubBoost's canonical node naming, group ordering and rule semantics, but never
  // pass Mihomo proxy-providers into sing-box: sing-box has no equivalent provider type.
  const clash = generateClashConfig({ ...options, proxyProviders: undefined });
  const nodes = Array.isArray(clash.proxies) ? clash.proxies : [];
  const converted = nodes.map(convertNode).filter((item): item is ConvertedNode => Boolean(item));
  const nodeOutbounds = converted.map((item) => item.outbound).filter((item): item is RecordValue => Boolean(item));
  const endpoints = converted.map((item) => item.endpoint).filter((item): item is RecordValue => Boolean(item));

  const userConfig = options.userConfig ?? {};
  const mixedPort = typeof clash["mixed-port"] === "number"
    ? clash["mixed-port"]
    : typeof userConfig.mixedPort === "number"
      ? userConfig.mixedPort
      : 7897;
  const allowLan = typeof clash["allow-lan"] === "boolean"
    ? clash["allow-lan"]
    : typeof userConfig.allowLan === "boolean"
      ? userConfig.allowLan
      : true;
  const testUrl = typeof userConfig.testUrl === "string" && userConfig.testUrl.trim()
    ? userConfig.testUrl.trim()
    : "https://www.gstatic.com/generate_204";
  const testInterval = typeof userConfig.testInterval === "number" ? userConfig.testInterval : 300;

  const baseTags = new Set<string>([
    "DIRECT",
    "REJECT",
    ...nodeOutbounds.map((item) => stringValue(item.tag)).filter((item): item is string => Boolean(item)),
    ...endpoints.map((item) => stringValue(item.tag)).filter((item): item is string => Boolean(item)),
  ]);
  const groupNames = (Array.isArray(clash["proxy-groups"]) ? clash["proxy-groups"] : [])
    .map((group) => isRecord(group) ? stringValue(group.name) : undefined)
    .filter((item): item is string => Boolean(item));
  const allPolicyTargets = new Set([...baseTags, ...groupNames]);
  const groups = (Array.isArray(clash["proxy-groups"]) ? clash["proxy-groups"] : [])
    .map((group) => convertGroup(group as ProxyGroup, allPolicyTargets, testUrl, testInterval))
    .filter((item): item is RecordValue => Boolean(item));

  const validPolicyTargets = new Set<string>([
    "DIRECT",
    "REJECT",
    ...nodeOutbounds.map((item) => stringValue(item.tag)).filter((item): item is string => Boolean(item)),
    ...endpoints.map((item) => stringValue(item.tag)).filter((item): item is string => Boolean(item)),
    ...groups.map((item) => stringValue(item.tag)).filter((item): item is string => Boolean(item)),
  ]);

  const ruleSets = convertRuleSets(clash);
  const knownRuleSetTags = new Set(
    ruleSets.map((item) => stringValue(item.tag)).filter((item): item is string => Boolean(item))
  );
  const routeRules: RecordValue[] = [];
  let final: string | undefined;
  for (const raw of Array.isArray(clash.rules) ? clash.rules : []) {
    if (typeof raw !== "string") continue;
    const convertedRule = convertRule(raw, validPolicyTargets, ruleSets, knownRuleSetTags);
    if (convertedRule.rule) routeRules.push(convertedRule.rule);
    if (convertedRule.final) final = convertedRule.final;
  }

  const listenerConfig = convertListeners(clash, mixedPort, allowLan);
  const outbounds = [
    { type: "direct", tag: "DIRECT" },
    // block remains a current outbound in sing-box 1.13 and is required as a selector member.
    // Routing rules use the modern reject action instead of the removed legacy special-outbound pattern.
    { type: "block", tag: "REJECT" },
    ...nodeOutbounds,
    ...groups,
  ];

  const fallbackFinal = groups.find((group) => group.type === "selector")?.tag
    ?? groups[0]?.tag
    ?? nodeOutbounds[0]?.tag
    ?? endpoints[0]?.tag
    ?? "DIRECT";

  return compact({
    log: { level: "info" },
    dns: {
      servers: [{ type: "local", tag: "local" }],
      final: "local",
    },
    inbounds: listenerConfig.inbounds,
    outbounds,
    ...(endpoints.length > 0 ? { endpoints } : {}),
    route: {
      default_domain_resolver: "local",
      rules: [...listenerConfig.rules, ...routeRules],
      rule_set: ruleSets,
      final: final && validPolicyTargets.has(final) ? final : fallbackFinal,
    },
  });
}

export function generateSingBoxJson(options: GenerateOptions): string {
  return `${JSON.stringify(generateSingBoxConfig(options), null, 2)}\n`;
}

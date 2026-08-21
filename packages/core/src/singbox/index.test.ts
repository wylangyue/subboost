import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ParsedNode } from "@subboost/core/types/node";
import {
  generateSingBoxConfig,
  generateSingBoxJson,
  hasSingBoxCompatibleNodes,
  isSingBoxCompatibleNode,
  SING_BOX_TARGET_VERSION,
} from "./index";

function node(value: Record<string, unknown>): ParsedNode {
  return value as unknown as ParsedNode;
}

const representativeNodes: ParsedNode[] = [
  node({
    name: "SS",
    type: "ss",
    server: "127.0.0.1",
    port: 10001,
    cipher: "aes-128-gcm",
    password: "password",
  }),
  node({
    name: "VMess gRPC",
    type: "vmess",
    server: "127.0.0.1",
    port: 10002,
    uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    cipher: "auto",
    tls: true,
    servername: "example.com",
    network: "grpc",
    "grpc-opts": { "grpc-service-name": "subboost" },
  }),
  node({
    name: "VLESS Reality",
    type: "vless",
    server: "127.0.0.1",
    port: 10002,
    uuid: "11111111-1111-4111-8111-111111111111",
    tls: true,
    servername: "example.com",
    "client-fingerprint": "chrome",
    flow: "xtls-rprx-vision",
    "reality-opts": {
      "public-key": "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789",
      "short-id": "0123456789abcdef",
    },
  }),
  node({
    name: "Trojan WS",
    type: "trojan",
    server: "127.0.0.1",
    port: 10003,
    password: "password",
    sni: "example.com",
    network: "ws",
    "ws-opts": { path: "/ws", headers: { Host: "example.com" } },
  }),
  node({
    name: "AnyTLS",
    type: "anytls",
    server: "127.0.0.1",
    port: 10004,
    password: "password",
    sni: "example.com",
  }),
  node({
    name: "Hysteria",
    type: "hysteria",
    server: "127.0.0.1",
    port: 10005,
    ports: "47000-48000",
    "auth-str": "password",
    up: "100 Mbps",
    down: "100 Mbps",
    sni: "example.com",
  }),
  node({
    name: "Hysteria2",
    type: "hysteria2",
    server: "127.0.0.1",
    port: 10005,
    ports: "443,47000-48000,48001:48002,70000-70001,bad",
    password: "password",
    sni: "example.com",
    obfs: "salamander",
    "obfs-password": "obfs-password",
  }),
  node({
    name: "TUIC",
    type: "tuic",
    server: "127.0.0.1",
    port: 10006,
    uuid: "22222222-2222-4222-8222-222222222222",
    password: "password",
    sni: "example.com",
    "congestion-controller": "bbr",
  }),
  node({
    name: "SOCKS5",
    type: "socks5",
    server: "127.0.0.1",
    port: 10007,
    username: "user",
    password: "password",
  }),
  node({
    name: "HTTPS",
    type: "https",
    server: "127.0.0.1",
    port: 10008,
    username: "user",
    password: "password",
    sni: "example.com",
  }),
  node({
    name: "SSH",
    type: "ssh",
    server: "127.0.0.1",
    port: 10009,
    username: "root",
    password: "password",
  }),
  node({
    name: "WireGuard",
    type: "wireguard",
    "private-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ip: "10.0.0.2/32",
    ipv6: "fd00::2/128",
    keepalive: 25,
    peers: [
      {
        server: "127.0.0.1",
        port: 10010,
        "public-key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "allowed-ips": ["0.0.0.0/0", "::/0"],
        reserved: "1,2,3",
      },
      {
        server: "127.0.0.2",
        port: 10011,
        "public-key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
        "allowed-ips": ["10.0.0.0/8"],
      },
    ],
  }),
];

function makeOptions() {
  return {
    nodes: representativeNodes,
    template: "minimal" as const,
    userConfig: {
      mixedPort: 17897,
      allowLan: false,
      testInterval: 300,
    },
  };
}

function hasSingBoxBinary(): boolean {
  try {
    execFileSync("sing-box", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("sing-box generator", () => {
  it("targets the current 1.13 schema instead of legacy compatibility fields", () => {
    expect(SING_BOX_TARGET_VERSION).toBe("1.13");
    const config = generateSingBoxConfig(makeOptions()) as any;

    expect(config.dns.servers).toEqual([
      { type: "udp", tag: "cn-dns", server: "223.5.5.5", server_port: 53 },
      {
        type: "https",
        tag: "proxy-dns",
        server: "1.1.1.1",
        server_port: 443,
        path: "/dns-query",
        tls: { enabled: true, server_name: "cloudflare-dns.com" },
        detour: expect.any(String),
      },
    ]);
    expect(config.dns.rules).toContainEqual({ domain_suffix: [".cn"], action: "route", server: "cn-dns" });
    expect(config.dns.rules).toContainEqual({
      rule_set: expect.arrayContaining(["geolocation-cn", "cn"]),
      action: "route",
      server: "cn-dns",
    });
    expect(config.dns.final).toBe("proxy-dns");
    expect(config.dns.strategy).toBe("ipv4_only");
    expect(config.route.default_domain_resolver).toBe("cn-dns");
    expect(config.route.auto_detect_interface).toBe(true);
    expect(config.inbounds[0]).toMatchObject({ type: "mixed", tag: "mixed-in", listen_port: 17897 });
    expect(config.inbounds[0]).not.toHaveProperty("sniff");
    expect(config.inbounds[1]).toMatchObject({
      type: "tun",
      tag: "tun-in",
      address: ["172.19.0.1/30"],
      auto_route: true,
      stack: "mixed",
    });
    expect(config.inbounds[1]).not.toHaveProperty("inet4_address");
    expect(config.inbounds[1]).not.toHaveProperty("inet6_address");
    expect(config.route.rules).toContainEqual({ inbound: "mixed-in", action: "sniff" });
    expect(config.route.rules).toContainEqual({ inbound: "tun-in", action: "sniff" });
    expect(config.route.rules).toContainEqual({
      type: "logical",
      mode: "or",
      rules: [{ protocol: "dns" }, { port: 53 }],
      action: "hijack-dns",
    });

    const wireGuardOutbound = config.outbounds.find((item: any) => item.type === "wireguard");
    expect(wireGuardOutbound).toBeUndefined();
    expect(config.endpoints).toContainEqual(expect.objectContaining({
      type: "wireguard",
      tag: "WireGuard",
      address: ["10.0.0.2/32", "fd00::2/128"],
      peers: [
        expect.objectContaining({ address: "127.0.0.1", port: 10010, reserved: [1, 2, 3], persistent_keepalive_interval: 25 }),
        expect.objectContaining({ address: "127.0.0.2", port: 10011, persistent_keepalive_interval: 25 }),
      ],
    }));

    const hysteria = config.outbounds.find((item: any) => item.tag === "Hysteria");
    expect(hysteria).toMatchObject({ server_ports: ["47000:48000"] });
    expect(hysteria).not.toHaveProperty("server_port");

    const hysteria2 = config.outbounds.find((item: any) => item.tag === "Hysteria2");
    expect(hysteria2).toMatchObject({ server_ports: ["443:443", "47000:48000", "48001:48002"] });
    expect(hysteria2).not.toHaveProperty("server_port");

    expect(config.route.rule_set.length).toBeGreaterThan(0);
    for (const ruleSet of config.route.rule_set) {
      expect(ruleSet.url).toMatch(/^https:\/\/raw\.githubusercontent\.com\/MetaCubeX\/meta-rules-dat\/sing\/geo\//);
      expect(ruleSet.url).not.toContain("/refs/heads/");
      expect(ruleSet.url).toMatch(/\.srs$/);
      expect(ruleSet.download_detour).toBe("DIRECT");
    }
    expect(config.route.rule_set).toContainEqual(expect.objectContaining({
      tag: "cn-ip",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs",
    }));
  });

  it("converts supported nodes and silently excludes transports sing-box cannot represent", () => {
    const config = generateSingBoxConfig({
      ...makeOptions(),
      nodes: [
        ...representativeNodes,
        node({
          name: "Unsupported XHTTP",
          type: "vless",
          server: "127.0.0.1",
          port: 10008,
          uuid: "33333333-3333-4333-8333-333333333333",
          tls: true,
          network: "xhttp",
          "xhttp-opts": { path: "/" },
        }),
        node({
          name: "Unsupported VLESS Encryption",
          type: "vless",
          server: "127.0.0.1",
          port: 10013,
          uuid: "44444444-4444-4444-8444-444444444444",
          tls: true,
          encryption: "mlkem768x25519plus.native/example",
        }),
        node({
          name: "Unsupported Certificate Fingerprint",
          type: "hysteria2",
          server: "127.0.0.1",
          port: 10014,
          password: "password",
          sni: "example.com",
          fingerprint: "AA:BB:CC",
          "skip-cert-verify": false,
        }),
      ],
    }) as any;

    const tags = config.outbounds.map((item: any) => item.tag).filter(Boolean);
    expect(tags).toEqual(expect.arrayContaining([
      "SS",
      "VMess gRPC",
      "VLESS Reality",
      "Trojan WS",
      "AnyTLS",
      "Hysteria",
      "Hysteria2",
      "TUIC",
      "SOCKS5",
      "HTTPS",
      "SSH",
    ]));
    expect(tags).not.toContain("Unsupported XHTTP");
    expect(tags).not.toContain("Unsupported VLESS Encryption");
    expect(tags).not.toContain("Unsupported Certificate Fingerprint");
    expect(config.endpoints.map((item: any) => item.tag)).toContain("WireGuard");
  });

  it("reports whether a saved node snapshot can produce a useful sing-box profile", () => {
    const unsupportedXhttp = node({
      name: "Unsupported XHTTP",
      type: "vless",
      server: "127.0.0.1",
      port: 10012,
      uuid: "33333333-3333-4333-8333-333333333333",
      tls: true,
      network: "xhttp",
      "xhttp-opts": { path: "/" },
    });

    const unsupportedEncryption = node({
      name: "Unsupported VLESS Encryption",
      type: "vless",
      server: "127.0.0.1",
      port: 10013,
      uuid: "44444444-4444-4444-8444-444444444444",
      tls: true,
      encryption: "mlkem768x25519plus.native/example",
    });
    const unsupportedFingerprint = node({
      name: "Unsupported Certificate Fingerprint",
      type: "hysteria2",
      server: "127.0.0.1",
      port: 10014,
      password: "password",
      sni: "example.com",
      fingerprint: "AA:BB:CC",
      "skip-cert-verify": false,
    });

    expect(isSingBoxCompatibleNode(representativeNodes[0])).toBe(true);
    expect(isSingBoxCompatibleNode(unsupportedXhttp)).toBe(false);
    expect(isSingBoxCompatibleNode(unsupportedEncryption)).toBe(false);
    expect(isSingBoxCompatibleNode(unsupportedFingerprint)).toBe(false);
    expect(hasSingBoxCompatibleNodes([unsupportedXhttp, unsupportedEncryption, unsupportedFingerprint])).toBe(false);
    expect(hasSingBoxCompatibleNodes([unsupportedXhttp, representativeNodes[0]])).toBe(true);
  });

  it.skipIf(!hasSingBoxBinary())("passes sing-box check with the installed binary", () => {
    const dir = mkdtempSync(join(tmpdir(), "subboost-singbox-"));
    const path = join(dir, "config.json");
    try {
      writeFileSync(path, generateSingBoxJson(makeOptions()), "utf8");
      expect(() => execFileSync("sing-box", ["check", "-c", path], { stdio: "pipe" })).not.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

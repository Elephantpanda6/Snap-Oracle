const std = @import("std");
const finding = @import("finding.zig");

pub const LicenseTier = enum {
    community_non_commercial,
    team_commercial,
    enterprise_commercial,

    pub fn toString(self: LicenseTier) []const u8 {
        return switch (self) {
            .community_non_commercial => "community_non_commercial",
            .team_commercial => "team",
            .enterprise_commercial => "enterprise",
        };
    }

    pub fn fromString(s: []const u8) ?LicenseTier {
        if (finding.eqlIgnoreCase(s, "community") or finding.eqlIgnoreCase(s, "community_non_commercial")) {
            return .community_non_commercial;
        }
        if (finding.eqlIgnoreCase(s, "team") or finding.eqlIgnoreCase(s, "team_commercial")) {
            return .team_commercial;
        }
        if (finding.eqlIgnoreCase(s, "enterprise") or finding.eqlIgnoreCase(s, "enterprise_commercial")) {
            return .enterprise_commercial;
        }
        return null;
    }
};

pub const FEATURE_SARIF_GATE: u32 = 1 << 0;
pub const FEATURE_DEPS_PAGESIZE: u32 = 1 << 1;
pub const FEATURE_SBOM_PORTSCAN: u32 = 1 << 2;
pub const FEATURE_FUZZ_CMIN_TRIAGE: u32 = 1 << 3;
pub const FEATURE_ALL: u32 = 0xFFFF_FFFF;

pub const LicenseToken = struct {
    org: []const u8,
    tier: []const u8,
    seats: u32 = 1,
    expires: []const u8,
    features_mask: u32 = FEATURE_ALL,
    pubkey_hex: []const u8,
    sig_hex: []const u8,
};

pub const VerifyOutcome = struct {
    valid: bool,
    reason: []const u8,
    tier: LicenseTier = .community_non_commercial,
    org: []const u8 = "",
    seats: u32 = 0,
    expires_ymd: u32 = 0,
};

pub fn canonicalMessage(allocator: std.mem.Allocator, org: []const u8, tier: LicenseTier, seats: u32, expires: []const u8, features_mask: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "SNAP-ORACLE-LIC|v1|{s}|{s}|{d}|{s}|0x{x:0>8}", .{
        org,
        tier.toString(),
        seats,
        expires,
        features_mask,
    });
}

pub fn parseYmd(s: []const u8) ?u32 {
    // Accepts "YYYY-MM-DD" or "YYYYMMDD"
    if (s.len == 10 and s[4] == '-' and s[7] == '-') {
        const y = std.fmt.parseInt(u32, s[0..4], 10) catch return null;
        const m = std.fmt.parseInt(u32, s[5..7], 10) catch return null;
        const d = std.fmt.parseInt(u32, s[8..10], 10) catch return null;
        if (m < 1 or m > 12 or d < 1 or d > 31) return null;
        return y * 10000 + m * 100 + d;
    }
    if (s.len == 8) {
        const v = std.fmt.parseInt(u32, s, 10) catch return null;
        return v;
    }
    return null;
}

pub fn generateDemoSignedTokenJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    org: []const u8,
    tier: LicenseTier,
    seats: u32,
    expires: []const u8,
    deterministic_seed: ?[32]u8,
) ![]u8 {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = if (deterministic_seed) |s|
        try Ed25519.KeyPair.generateDeterministic(s)
    else
        Ed25519.KeyPair.generate(io);

    const msg = try canonicalMessage(allocator, org, tier, seats, expires, FEATURE_ALL);
    defer allocator.free(msg);

    const sig = try kp.sign(msg, null);
    const pk_bytes = kp.public_key.toBytes();
    const sig_bytes = sig.toBytes();

    const pk_hex = bytesToHex32(&pk_bytes);
    const sig_hex = bytesToHex64(&sig_bytes);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n  \"org\": ");
    try finding.appendJsonEscaped(&out, allocator, org);
    try out.appendSlice(allocator, ",\n  \"tier\": ");
    try finding.appendJsonEscaped(&out, allocator, tier.toString());
    const mid = try std.fmt.allocPrint(allocator, ",\n  \"seats\": {d},\n  \"expires\": ", .{seats});
    defer allocator.free(mid);
    try out.appendSlice(allocator, mid);
    try finding.appendJsonEscaped(&out, allocator, expires);
    const tail = try std.fmt.allocPrint(allocator, ",\n  \"features_mask\": {d},\n  \"pubkey_hex\": \"{s}\",\n  \"sig_hex\": \"{s}\"\n}}\n", .{
        FEATURE_ALL,
        pk_hex,
        sig_hex,
    });
    defer allocator.free(tail);
    try out.appendSlice(allocator, tail);

    return out.toOwnedSlice(allocator);
}

pub fn verifyTokenJson(
    allocator: std.mem.Allocator,
    json_bytes: []const u8,
    expected_pubkey_hex: ?[]const u8,
    current_ymd: u32,
) !VerifyOutcome {
    const parsed = std.json.parseFromSlice(LicenseToken, allocator, json_bytes, .{
        .ignore_unknown_fields = true,
    }) catch return .{ .valid = false, .reason = "Malformed license JSON" };
    defer parsed.deinit();

    const tok = parsed.value;
    const tier = LicenseTier.fromString(tok.tier) orelse return .{
        .valid = false,
        .reason = "Unknown license tier",
    };

    const exp_ymd = parseYmd(tok.expires) orelse return .{
        .valid = false,
        .reason = "Invalid expiry date (expected YYYY-MM-DD)",
    };

    if (current_ymd > 0 and exp_ymd < current_ymd) {
        return .{
            .valid = false,
            .reason = "License has expired",
            .tier = tier,
            .expires_ymd = exp_ymd,
            .seats = tok.seats,
        };
    }

    if (tok.pubkey_hex.len != 64 or tok.sig_hex.len != 128) {
        return .{ .valid = false, .reason = "Invalid Ed25519 key or signature length" };
    }

    if (expected_pubkey_hex) |exp_pk| {
        if (!finding.eqlIgnoreCase(tok.pubkey_hex, exp_pk)) {
            return .{ .valid = false, .reason = "Token public key does not match pinned issuer key" };
        }
    }

    var pk_raw: [32]u8 = undefined;
    var sig_raw: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&pk_raw, tok.pubkey_hex) catch return .{ .valid = false, .reason = "Invalid hex in pubkey_hex" };
    _ = std.fmt.hexToBytes(&sig_raw, tok.sig_hex) catch return .{ .valid = false, .reason = "Invalid hex in sig_hex" };

    const Ed25519 = std.crypto.sign.Ed25519;
    const pk = Ed25519.PublicKey.fromBytes(pk_raw) catch return .{ .valid = false, .reason = "Non-canonical Ed25519 public key" };
    const sig = Ed25519.Signature.fromBytes(sig_raw);

    const msg = try canonicalMessage(allocator, tok.org, tier, tok.seats, tok.expires, tok.features_mask);
    defer allocator.free(msg);

    sig.verify(msg, pk) catch {
        return .{ .valid = false, .reason = "Ed25519 signature verification FAILED" };
    };

    return .{
        .valid = true,
        .reason = "Valid offline Ed25519-signed license",
        .tier = tier,
        .org = tok.org,
        .seats = tok.seats,
        .expires_ymd = exp_ymd,
    };
}

fn bytesToHex32(bytes: *const [32]u8) [64]u8 {
    const hex = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (bytes.*, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xF];
    }
    return out;
}

fn bytesToHex64(bytes: *const [64]u8) [128]u8 {
    const hex = "0123456789abcdef";
    var out: [128]u8 = undefined;
    for (bytes.*, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xF];
    }
    return out;
}

pub fn printTerms() void {
    std.debug.print(
        \\=== Snap-Oracle Commercial & Non-Commercial Licensing Summary ===
        \\Author / Licensor : Elephantpanda6
        \\Non-Commercial Tier : Free for personal, academic, and individual non-commercial security research.
        \\Commercial Tier     : Requires a paid commercial license per organization/seat before internal, CI/CD,
        \\                      client-facing, or SaaS business use.
        \\Authorized Use Only : Only scan/fuzz binaries and source repositories you own or have written authorization to test.
        \\Liability & Warranty: PROVIDED "AS IS" WITHOUT WARRANTY; Author is held harmless and indemnified against
        \\                      misuse, operational downtime, or third-party claims (see LICENSE for full legal text).
        \\
    , .{});
}

pub fn runLicenseCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0 or std.mem.eql(u8, args[0], "status") or std.mem.eql(u8, args[0], "terms")) {
        printTerms();
        return 0;
    }

    const sub = args[0];
    if (std.mem.eql(u8, sub, "keygen-demo")) {
        var org: []const u8 = "Acme ARM64 Corp (Evaluation Demo)";
        var tier: LicenseTier = .enterprise_commercial;
        var seats: u32 = 25;
        var expires: []const u8 = "2027-12-31";
        var out_path: ?[]const u8 = null;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--org") and i + 1 < args.len) {
                i += 1;
                org = args[i];
            } else if (std.mem.eql(u8, args[i], "--tier") and i + 1 < args.len) {
                i += 1;
                tier = LicenseTier.fromString(args[i]) orelse .enterprise_commercial;
            } else if (std.mem.eql(u8, args[i], "--seats") and i + 1 < args.len) {
                i += 1;
                seats = std.fmt.parseInt(u32, args[i], 10) catch 25;
            } else if (std.mem.eql(u8, args[i], "--expires") and i + 1 < args.len) {
                i += 1;
                expires = args[i];
            } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
                i += 1;
                out_path = args[i];
            }
        }

        const json = try generateDemoSignedTokenJson(io, allocator, org, tier, seats, expires, null);
        defer allocator.free(json);
        if (out_path) |p| {
            try finding.writeOutputFile(io, p, json);
            std.debug.print("[license] wrote self-signed demo token to {s}\n", .{p});
        } else {
            finding.writeStdout(io, json);
        }
        return 0;
    }

    if (std.mem.eql(u8, sub, "verify")) {
        if (args.len < 2) {
            std.debug.print("Usage: snap-oracle license verify <license.json> [--pubkey <hex64>] [--today YYYY-MM-DD]\n", .{});
            return 2;
        }
        const path = args[1];
        var expected_pk: ?[]const u8 = null;
        var today_ymd: u32 = 0;

        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--pubkey") and i + 1 < args.len) {
                i += 1;
                expected_pk = args[i];
            } else if (std.mem.eql(u8, args[i], "--today") and i + 1 < args.len) {
                i += 1;
                today_ymd = parseYmd(args[i]) orelse 0;
            }
        }

        const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024));
        defer allocator.free(raw);

        const res = try verifyTokenJson(allocator, raw, expected_pk, today_ymd);
        std.debug.print("[license] valid={any} | tier={s} | seats={d} | expires={d} | reason={s}\n", .{
            res.valid,
            res.tier.toString(),
            res.seats,
            res.expires_ymd,
            res.reason,
        });
        return if (res.valid) 0 else 1;
    }

    std.debug.print("Usage: snap-oracle license <status|terms|verify <file>|keygen-demo [--out file]>\n", .{});
    return 2;
}

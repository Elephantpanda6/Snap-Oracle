const std = @import("std");
const mutator = @import("mutator.zig");

pub const Entry = struct {
    data: []u8,
    edge_hits: usize,
};

pub const Corpus = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry),
    seen_hashes: std.AutoHashMapUnmanaged(u64, void),
    max_seed_bytes: usize = 64 * 1024,

    pub fn init(allocator: std.mem.Allocator) Corpus {
        return .{
            .allocator = allocator,
            .entries = std.ArrayList(Entry).empty,
            .seen_hashes = .empty,
        };
    }

    pub fn deinit(self: *Corpus) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.data);
        }
        self.entries.deinit(self.allocator);
        self.seen_hashes.deinit(self.allocator);
    }

    pub fn addSeed(self: *Corpus, data: []const u8, edge_hits: usize) !bool {
        const capped = data[0..@min(data.len, self.max_seed_bytes)];
        const hash = std.hash.Wyhash.hash(0, capped);
        if (self.seen_hashes.contains(hash)) {
            return false;
        }

        try self.seen_hashes.ensureUnusedCapacity(self.allocator, 1);
        const copy = try self.allocator.dupe(u8, capped);
        errdefer self.allocator.free(copy);

        try self.entries.append(self.allocator, .{
            .data = copy,
            .edge_hits = edge_hits,
        });
        self.seen_hashes.putAssumeCapacity(hash, {});
        return true;
    }

    pub fn loadDir(self: *Corpus, io: std.Io, dir_path: []const u8) !usize {
        var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return 0;
        defer dir.close(io);

        var it = dir.iterate();
        var loaded: usize = 0;
        while (it.next(io) catch null) |entry| {
            if (entry.kind != .file) continue;
            const data = dir.readFileAlloc(io, entry.name, self.allocator, .limited(self.max_seed_bytes)) catch continue;
            defer self.allocator.free(data);

            if (try self.addSeed(data, 0)) {
                loaded += 1;
            }
        }
        return loaded;
    }

    pub fn ensureNonEmpty(self: *Corpus) !void {
        if (self.entries.items.len == 0) {
            const default_seed: [16]u8 = @splat(0x41);
            _ = try self.addSeed(&default_seed, 0);
        }
    }

    pub fn pickNext(self: *Corpus, rng: *mutator.Rng) []const u8 {
        const n = self.entries.items.len;
        if (n == 0) return &.{};
        if (rng.below(100) < 70) {
            return self.entries.items[n - 1].data;
        }
        return self.entries.items[rng.below(n)].data;
    }

    /// Energy-weighted corpus scheduling favoring recently discovered and high-edge-yield seeds.
    pub fn pickWeighted(self: *Corpus, rng: *mutator.Rng) []const u8 {
        const n = self.entries.items.len;
        if (n == 0) return &.{};
        if (rng.below(100) < 55) {
            return self.entries.items[n - 1].data;
        }
        var total_weight: usize = 0;
        for (self.entries.items, 0..) |e, idx| {
            total_weight += 1 + @min(e.edge_hits, 8) + if (idx * 2 >= n) @as(usize, 2) else 0;
        }
        var target = rng.below(total_weight);
        for (self.entries.items, 0..) |e, idx| {
            const w = 1 + @min(e.edge_hits, 8) + if (idx * 2 >= n) @as(usize, 2) else 0;
            if (target < w) return e.data;
            target -= w;
        }
        return self.entries.items[n - 1].data;
    }

    pub fn allSeeds(self: *const Corpus) []const Entry {
        return self.entries.items;
    }

    pub fn count(self: *const Corpus) usize {
        return self.entries.items.len;
    }
};

test "corpus addSeed deduplicates via Wyhash" {
    var corpus = Corpus.init(std.testing.allocator);
    defer corpus.deinit();

    try std.testing.expect(try corpus.addSeed("alpha", 1));
    try std.testing.expect(!try corpus.addSeed("alpha", 2));
    try std.testing.expect(try corpus.addSeed("beta", 3));
    try std.testing.expectEqual(@as(usize, 2), corpus.count());
}

test "corpus ensureNonEmpty adds 16-byte 0x41 seed when empty" {
    var corpus = Corpus.init(std.testing.allocator);
    defer corpus.deinit();

    try corpus.ensureNonEmpty();
    try std.testing.expectEqual(@as(usize, 1), corpus.count());
    const expected_seed: [16]u8 = @splat(0x41);
    try std.testing.expectEqualSlices(u8, &expected_seed, corpus.entries.items[0].data);

    try corpus.ensureNonEmpty();
    try std.testing.expectEqual(@as(usize, 1), corpus.count());
}

test "corpus pickNext and pickWeighted schedule seeds properly" {
    var corpus = Corpus.init(std.testing.allocator);
    defer corpus.deinit();

    _ = try corpus.addSeed("first", 0);
    _ = try corpus.addSeed("second", 1);
    _ = try corpus.addSeed("third", 5);

    var rng = mutator.Rng.init(0x123456789abcdef0);
    var latest_hits: usize = 0;
    const trials: usize = 1000;
    for (0..trials) |_| {
        const picked = corpus.pickNext(&rng);
        if (std.mem.eql(u8, picked, "third")) {
            latest_hits += 1;
        }
    }
    try std.testing.expect(latest_hits >= 650);
    try std.testing.expect(corpus.pickWeighted(&rng).len > 0);
    try std.testing.expectEqual(@as(usize, 3), corpus.allSeeds().len);
}

test "corpus loadDir loads files and handles missing dir gracefully" {
    var corpus = Corpus.init(std.testing.allocator);
    defer corpus.deinit();

    const missing_count = try corpus.loadDir(std.testing.io, "nonexistent_corpus_dir_xyz_12345");
    try std.testing.expectEqual(@as(usize, 0), missing_count);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "seed1.bin", .data = "SEED_ONE" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "seed2.bin", .data = "SEED_TWO" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "seed2_dup.bin", .data = "SEED_TWO" });

    const tmp_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer std.testing.allocator.free(tmp_path);

    const loaded = try corpus.loadDir(std.testing.io, tmp_path);
    try std.testing.expectEqual(@as(usize, 2), loaded);
    try std.testing.expectEqual(@as(usize, 2), corpus.count());
}

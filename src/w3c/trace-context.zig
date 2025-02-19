//! https://www.w3.org/TR/trace-context/

const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

/// https://www.w3.org/TR/trace-context/#traceparent-header
pub const TraceParent = struct {
    version: Version = .{},
    trace_id: TraceId,
    parent_id: ParentId,
    trace_flags: TraceFlags,

    pub const header_name = "traceparent";

    pub const string_field_separator = "-";

    /// https://www.w3.org/TR/trace-context/#version
    pub const Version = struct {
        byte: u8 = 0,

        pub const invalid = .{ .byte = 0xFF };

        pub fn isValid(self: @This()) bool {
            return self.byte != invalid.byte;
        }

        pub const HexBytes = [2]u8;

        pub fn toHex(self: @This()) HexBytes {
            return std.fmt.bytesToHex([_]u8{self.byte}, .lower);
        }

        pub fn fromHex(hex: HexBytes) error{InvalidCharacter}!@This() {
            return .{ .byte = (try hexToBytes(hex))[0] };
        }

        pub const Error = error{UnsupportedVersion};

        pub const String = [
            @sizeOf(TraceId.HexBytes) +
                string_field_separator.len +
                @sizeOf(ParentId.HexBytes) +
                string_field_separator.len +
                @sizeOf(TraceFlags.HexBytes)
        ]u8;

        /// https://www.w3.org/TR/trace-context/#version-format
        pub fn toString(
            self: @This(),
            trace_id: TraceId,
            parent_id: ParentId,
            trace_flags: TraceFlags,
        ) Error!@This().String {
            return switch (self.byte) {
                0 => trace_id.toHex() ++
                    string_field_separator.* ++
                    parent_id.toHex() ++
                    string_field_separator.* ++
                    trace_flags.toHex(),
                else => error.UnsupportedVersion,
            };
        }

        pub fn fromString(self: @This(), string: @This().String) (Error || error{InvalidCharacter})!struct {
            TraceId,
            ParentId,
            TraceFlags,
        } {
            var stream = std.io.fixedBufferStream(&string);
            const reader = stream.reader();
            defer std.debug.assert(reader.readByte() == error.EndOfStream);

            return switch (self.byte) {
                0 => blk: {
                    const trace_id = try TraceId.fromHex(reader.readBytesNoEof(@sizeOf(TraceId.HexBytes)) catch unreachable);
                    if (!(reader.isBytes(string_field_separator) catch unreachable)) return error.InvalidCharacter;
                    const parent_id = try ParentId.fromHex(reader.readBytesNoEof(@sizeOf(ParentId.HexBytes)) catch unreachable);
                    if (!(reader.isBytes(string_field_separator) catch unreachable)) return error.InvalidCharacter;
                    const trace_flags = try TraceFlags.fromHex(reader.readBytesNoEof(@sizeOf(TraceFlags.HexBytes)) catch unreachable);
                    break :blk .{ trace_id, parent_id, trace_flags };
                },
                else => error.UnsupportedVersion,
            };
        }
    };

    /// https://www.w3.org/TR/trace-context/#trace-id
    pub const TraceId = Id(16);

    /// https://www.w3.org/TR/trace-context/#parent-id
    pub const ParentId = Id(8);

    fn Id(num_bytes: comptime_int) type {
        return struct {
            bytes: [num_bytes]u8,

            pub const invalid = @This(){ .bytes = [_]u8{0} ** num_bytes };

            pub fn isValid(self: @This()) bool {
                return !std.mem.allEqual(u8, &self.bytes, 0);
            }

            pub const HexBytes = [num_bytes * 2]u8;

            pub fn toHex(self: @This()) HexBytes {
                return std.fmt.bytesToHex(self.bytes, .lower);
            }

            pub fn fromHex(hex: HexBytes) error{InvalidCharacter}!@This() {
                return .{ .bytes = try hexToBytes(hex) };
            }
        };
    }

    /// https://www.w3.org/TR/trace-context/#trace-flags
    pub const TraceFlags = packed struct(u8) {
        /// https://www.w3.org/TR/trace-context/#sampled-flag
        sampled: bool = false,
        /// https://www.w3.org/TR/trace-context/#other-flags
        _: u7 = 0,

        pub const HexBytes = [@sizeOf(@This()) * 2]u8;

        pub fn toHex(self: @This()) HexBytes {
            return std.fmt.bytesToHex(std.mem.asBytes(&self), .lower);
        }

        pub fn fromHex(hex: HexBytes) error{InvalidCharacter}!@This() {
            return std.mem.bytesToValue(@This(), &(try hexToBytes(hex)));
        }

        pub fn toInt(self: @This()) @typeInfo(@This()).Struct.backing_integer.? {
            return @bitCast(self);
        }

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            try write_stream.beginObject();

            inline for (comptime std.enums.values(std.meta.FieldEnum(@This()))) |field| {
                if (field == ._) continue;

                const name = @tagName(field);

                try write_stream.objectField(name);
                try write_stream.write(@field(self, name));
            }

            try write_stream.endObject();
        }
    };

    pub const String = [
        @sizeOf(Version.HexBytes) +
            string_field_separator.len +
            @sizeOf(Version.String)
    ]u8;

    pub fn fromString(string: String) (Version.Error || error{InvalidCharacter})!@This() {
        var stream = std.io.fixedBufferStream(&string);
        const reader = stream.reader();
        defer std.debug.assert(reader.readByte() == error.EndOfStream);

        const version = try Version.fromHex(reader.readBytesNoEof(@sizeOf(Version.HexBytes)) catch unreachable);
        if (!(reader.isBytes(string_field_separator) catch unreachable)) return error.InvalidCharacter;
        const trace_id, const parent_id, const trace_flags = try version.fromString(reader.readBytesNoEof(@sizeOf(Version.String)) catch unreachable);

        return .{
            .version = version,
            .trace_id = trace_id,
            .parent_id = parent_id,
            .trace_flags = trace_flags,
        };
    }

    // https://www.w3.org/TR/trace-context/#examples-of-http-traceparent-headers
    test fromString {
        try std.testing.expectEqual(@This(){
            .trace_id = .{ .bytes = .{ 0x4B, 0xF9, 0x2F, 0x35, 0x77, 0xB3, 0x4D, 0xA6, 0xA3, 0xCE, 0x92, 0x9D, 0x0E, 0x0E, 0x47, 0x36 } },
            .parent_id = .{ .bytes = .{ 0x00, 0xF0, 0x67, 0xAA, 0x0B, 0xA9, 0x02, 0xB7 } },
            .trace_flags = .{ .sampled = true },
        }, try fromString("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".*));
    }

    /// https://www.w3.org/TR/trace-context/#traceparent-header-field-values
    pub fn toString(self: @This()) Version.Error!String {
        return self.version.toHex() ++
            string_field_separator.* ++
            try self.version.toString(self.trace_id, self.parent_id, self.trace_flags);
    }

    // https://www.w3.org/TR/trace-context/#examples-of-http-traceparent-headers
    test toString {
        try std.testing.expectEqualStrings("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", &(try (@This(){
            .trace_id = .{ .bytes = .{ 0x4B, 0xF9, 0x2F, 0x35, 0x77, 0xB3, 0x4D, 0xA6, 0xA3, 0xCE, 0x92, 0x9D, 0x0E, 0x0E, 0x47, 0x36 } },
            .parent_id = .{ .bytes = .{ 0x00, 0xF0, 0x67, 0xAA, 0x0B, 0xA9, 0x02, 0xB7 } },
            .trace_flags = .{ .sampled = true },
        }).toString()));
    }

    fn hexToBytes(hex: anytype) error{InvalidCharacter}![hex.len / 2]u8 {
        var bytes: [hex.len / 2]u8 = undefined;
        const bytes_slice = std.fmt.hexToBytes(&bytes, &hex) catch |err| switch (err) {
            error.InvalidLength, error.NoSpaceLeft => unreachable,
            error.InvalidCharacter => |e| return e,
        };
        std.debug.assert(bytes_slice.len == bytes.len);
        return bytes;
    }
};

// TODO Should this copy keys and values to own them like `std.BufMap`?
/// https://www.w3.org/TR/trace-context/#tracestate-header-field-values
pub const TraceState = struct {
    /// Modify only using the methods exposed by this type
    /// or take care to uphold the rules layed out in the specification:
    /// https://www.w3.org/TR/trace-context/#mutating-the-tracestate-field
    ///
    /// To move an entry to the start, set its key's `position` to zero and call `sort()`.
    /// Alternatively you can use `reNumber()` if you insert afterwards.
    entries: Entries = .{},

    pub const Entries = std.ArrayHashMapUnmanaged(Key, []const u8, struct {
        pub fn eql(_: @This(), a: Key, b: Key, _: usize) bool {
            return a.name.eql(b.name);
        }

        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(@tagName(std.meta.activeTag(key.name)));
            switch (key.name) {
                .simple => |s| hasher.update(s),
                .multi_tenant => |mt| {
                    hasher.update(mt.tenant);
                    hasher.update(Key.Name.MultiTenant.separator);
                    hasher.update(mt.system);
                },
            }
            return @truncate(hasher.final());
        }
    }, false);

    pub const header_name = "tracestate";

    pub const InvalidEntryError = Key.Name.InvalidError || InvalidValueError;
    pub const InvalidValueError = error{InvalidTraceStateValue};
    pub const PruneError = error{
        /// The `PruneLimits` remove all entries.
        TraceStateLimitsTooAggressive,
    } || if (std.debug.runtime_safety) PruneLimits.InvalidError else error{};

    pub const max_entries = 32;
    pub const max_value_len = 256;

    pub const Key = struct {
        /// Not taken into account for the hash and equality.
        position: Position = undefined,
        name: Name,

        pub const Position = std.math.IntFittingRange(0, max_entries - 1);

        /// https://www.w3.org/TR/trace-context/#key
        pub const Name = union(enum) {
            simple: []const u8,
            multi_tenant: MultiTenant,

            pub const InvalidError = error{InvalidTraceStateKey};

            pub const MultiTenant = struct {
                tenant: []const u8,
                system: []const u8,

                comptime {
                    std.debug.assert(max_tenant_len + separator.len + max_system_len == max_len);
                }

                pub const separator = "@";

                pub const max_tenant_len = 241;
                pub const max_system_len = 14;

                pub fn validate(self: @This()) InvalidError!void {
                    if (self.tenant.len == 0 or
                        self.tenant.len > MultiTenant.max_tenant_len or
                        self.system.len == 0 or
                        self.system.len > MultiTenant.max_system_len or
                        (!std.ascii.isLower(self.tenant[0]) and !std.ascii.isDigit(self.tenant[0])) or
                        !isValidPart(self.tenant) or
                        !std.ascii.isLower(self.system[0]) or
                        !isValidPart(self.system))
                        return error.InvalidTraceStateKey;
                }

                pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
                    try writer.writeAll(self.tenant);
                    try writer.writeAll(separator);
                    try writer.writeAll(self.system);
                }

                /// The number of bytes that `toString()` will write.
                pub fn stringLength(self: @This()) usize {
                    return self.tenant.len + separator.len + self.system.len;
                }

                pub const FromStringError = InvalidError || error{UnexpectedEndOfInput};

                pub fn fromString(string: []const u8) FromStringError!@This() {
                    var iter = std.mem.splitSequence(u8, string, separator);

                    const tenant = iter.first();
                    const system = iter.next() orelse
                        return error.UnexpectedEndOfInput;

                    if (iter.rest().len != 0)
                        return error.InvalidTraceStateKey;

                    const self = @This(){
                        .tenant = tenant,
                        .system = system,
                    };

                    try self.validate();

                    return self;
                }
            };

            pub const max_len = 256;

            pub fn validate(self: @This()) InvalidError!void {
                return switch (self) {
                    .simple => |key| if (key.len == 0 or
                        key.len > max_len or
                        !std.ascii.isLower(key[0]) or
                        !isValidPart(key[1..]))
                        error.InvalidTraceStateKey,
                    .multi_tenant => |multi_tenant| multi_tenant.validate(),
                };
            }

            fn isValidPart(chars: []const u8) bool {
                for (chars) |char|
                    switch (char) {
                        '_', '-', '*', '/' => {},
                        else => |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c))
                            return false,
                    };
                return true;
            }

            pub fn eql(self: @This(), other: @This()) bool {
                if (std.meta.activeTag(self) != std.meta.activeTag(other))
                    return false;

                return switch (self) {
                    .simple => |s| std.mem.eql(u8, s, other.simple),
                    .multi_tenant => |mt| std.mem.eql(u8, mt.tenant, other.multi_tenant.tenant) and
                        std.mem.eql(u8, mt.system, other.multi_tenant.system),
                };
            }

            pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
                if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
                    try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

                return switch (self) {
                    .simple => |name| try writer.writeAll(name),
                    .multi_tenant => |mt| try mt.toString(writer),
                };
            }

            /// The number of bytes that `toString()` will write.
            pub fn stringLength(self: @This()) usize {
                return switch (self) {
                    .simple => |name| name.len,
                    .multi_tenant => |mt| mt.tenant.len + MultiTenant.separator.len + mt.system.len,
                };
            }

            pub fn fromString(string: []const u8) InvalidError!@This() {
                return .{ .multi_tenant = MultiTenant.fromString(string) catch |err| switch (err) {
                    else => |e| return e,
                    error.UnexpectedEndOfInput => {
                        const self = @This(){ .simple = string };
                        try self.validate();
                        return self;
                    },
                } };
            }
        };
    };

    pub const KV = std.meta.FieldType(@This(), .entries).KV;

    pub const string_separator = ",";
    pub const string_assignment = "=";

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    /// https://www.w3.org/TR/trace-context/#value
    pub fn validateValue(value: []const u8) InvalidValueError!void {
        if (value.len > max_value_len)
            return error.InvalidTraceStateValue;

        for (value) |char|
            if (!std.ascii.isPrint(char) or switch (char) {
                ',', '=' => true,
                else => false,
            })
                return error.InvalidTraceStateValue;

        if (value[value.len - 1] == ' ')
            return error.InvalidTraceStateValue;
    }

    /// https://www.w3.org/TR/trace-context/#mutating-the-tracestate-field
    pub fn put(
        self: *@This(),
        allocator: std.mem.Allocator,
        name: Key.Name,
        value: []const u8,
    ) (InvalidEntryError || std.mem.Allocator.Error)!void {
        try name.validate();
        try validateValue(value);

        self.reNumber(1);

        // Set position to zero to move this to the front.
        //
        // We cannot just use `self.entries.put()`
        // because that does not overwrite the key
        // so the position is not updated.
        const gop = try self.entries.getOrPut(allocator, .{ .position = 0, .name = name });
        if (gop.found_existing) gop.key_ptr.position = 0;
        gop.value_ptr.* = value;
    }

    pub const PruneLimits = struct {
        entries: std.math.IntFittingRange(1, max_entries) = max_entries,
        string_len: ?std.math.IntFittingRange(min_string_len, std.math.maxInt(usize)) = null,

        pub const InvalidError = error{TraceStateLimitsInvalid};

        pub const min_string_len = 512;

        /// Entries bigger than this are removed first.
        pub const big_entry_threshold = 128;

        pub fn valid(self: @This()) @This() {
            return .{
                .entries = @max(1, @min(self.entries, max_entries)),
                .string_len = if (self.string_len) |string_len| @max(min_string_len, string_len),
            };
        }

        pub fn validate(self: @This()) InvalidError!void {
            if (self.entries < 1 or self.entries > max_entries or
                if (self.string_len) |string_len| string_len < min_string_len else false)
                return error.TraceStateLimitsInvalid;
        }
    };

    /// https://www.w3.org/TR/trace-context/#tracestate-limits
    /// Returns the number of entries that were pruned.
    pub fn prune(self: *@This(), limits: PruneLimits) PruneError!usize {
        var num_pruned: usize = 0;
        try self.pruneCallback(limits, *usize, error{}, &num_pruned, struct {
            fn call(num_pruned_ptr: *usize, _: KV) !void {
                num_pruned_ptr.* += 1;
            }
        }.call);
        return num_pruned;
    }

    /// https://www.w3.org/TR/trace-context/#tracestate-limits
    pub fn pruneCallback(
        self: *@This(),
        limits: PruneLimits,
        comptime CallbackCtx: type,
        comptime CallbackError: type,
        callback_ctx: CallbackCtx,
        callback: fn (CallbackCtx, KV) CallbackError!void,
    ) (PruneError || CallbackError)!void {
        if (std.debug.runtime_safety and !builtin.is_test)
            try limits.validate();

        var sorted = false;
        var string_len = self.stringLength();
        var has_big_entries = true;
        var last_big_entry_idx: ?usize = null;
        prune: while (self.entries.count() > limits.entries or
            if (limits.string_len) |msl| string_len > msl else false)
        {
            if (self.entries.count() == 1)
                return error.TraceStateLimitsTooAggressive;

            const kv = if (has_big_entries) kv: {
                for (last_big_entry_idx orelse 0..self.entries.count()) |idx| {
                    const data = self.entries.entries.get(idx);
                    const kv = KV{ .key = data.key, .value = data.value };

                    const kv_string_len = kvStringLength(kv);
                    if (kv_string_len > PruneLimits.big_entry_threshold) {
                        self.entries.orderedRemoveAt(idx);

                        string_len -= kv_string_len;
                        last_big_entry_idx = idx;

                        break :kv kv;
                    }
                } else {
                    has_big_entries = false;
                    continue :prune;
                }
            } else kv: {
                if (!sorted) {
                    self.sort();
                    sorted = true;
                }
                const kv = self.entries.pop();

                string_len -= kvStringLength(kv);

                break :kv kv;
            };

            if (self.entries.count() != 0)
                string_len -= string_separator.len;

            try callback(callback_ctx, kv);
        }
    }

    test prune {
        const allocator = std.testing.allocator;

        var self = @This(){};
        defer self.deinit(allocator);

        try self.put(allocator, .{ .simple = "big" }, "a" ** (PruneLimits.big_entry_threshold + 1));
        try self.put(allocator, .{
            .multi_tenant = .{
                .tenant = "tenant",
                .system = "system",
            },
        }, "multi_tenant");

        var pruned: ?KV = null;
        try self.pruneCallback(
            .{ .string_len = self.stringLength() - 1 },
            *@TypeOf(pruned),
            error{TestUnexpectedResult},
            &pruned,
            struct {
                fn call(pruned_ptr: *@TypeOf(pruned), kv: KV) !void {
                    try std.testing.expect(pruned_ptr.* == null);
                    pruned_ptr.* = kv;
                }
            }.call,
        );

        try std.testing.expect(pruned != null);
        try std.testing.expectEqual(Key.Name{ .simple = "big" }, pruned.?.key.name);

        var iter = self.entries.iterator();
        try std.testing.expectEqual(Key.Name{
            .multi_tenant = .{
                .tenant = "tenant",
                .system = "system",
            },
        }, iter.next().?.key_ptr.name);
        try std.testing.expect(iter.next() == null);
    }

    /// Assigns all entries their current actual position, starting with `start`.
    /// Useful to bump a certain entry to the front.
    pub fn reNumber(self: *@This(), start: std.meta.FieldType(Key, .position)) void {
        for (self.entries.keys(), start..) |*key, position|
            key.position = @intCast(position);
    }

    /// Call this before iterating over the entries
    /// if you want to iterate in the correct order.
    pub fn sort(self: *@This()) void {
        self.entries.sort(struct {
            keys: []Key,

            pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                return ctx.keys[a_index].position < ctx.keys[b_index].position;
            }
        }{ .keys = self.entries.keys() });
    }

    /// Call `sort()` first to get a result that follows the specification!
    pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
        if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
            try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (iter.index != 1) try writer.writeAll(string_separator);
            try entry.key_ptr.name.toString(writer);
            try writer.writeAll(string_assignment);
            try writer.writeAll(entry.value_ptr.*);
        }
    }

    /// The number of bytes that `toString()` will write.
    pub fn stringLength(self: @This()) usize {
        var string_len: usize = 0;

        {
            var iter = self.entries.iterator();
            while (iter.next()) |entry|
                string_len += kvStringLength(.{ .key = entry.key_ptr.*, .value = entry.value_ptr.* });
        }

        string_len += (self.entries.count() -| 1) * string_separator.len;

        return string_len;
    }

    test toString {
        const allocator = std.testing.allocator;

        var self = @This(){};
        defer self.deinit(allocator);

        try self.put(allocator, .{ .simple = "simple" }, "simple");
        try self.put(allocator, .{
            .multi_tenant = .{
                .tenant = "tenant",
                .system = "system",
            },
        }, "multi_tenant");

        self.sort();

        try std.testing.expectFmt(
            "tenant@system=multi_tenant," ++
                "simple=simple",
            "{}",
            .{self},
        );
    }

    pub fn kvStringLength(kv: KV) usize {
        return kv.key.name.stringLength() +
            string_assignment.len +
            kv.value.len;
    }

    pub const StringIterator = struct {
        pairs_iterator: std.mem.SplitIterator(u8, .sequence),

        pub const Error = InvalidEntryError || error{UnexpectedEndOfInput};

        pub const Entry = struct {
            name: Key.Name,
            value: []const u8,
        };

        pub fn next(self: *@This()) Error!?Entry {
            const pair_string = std.mem.trim(
                u8,
                self.pairs_iterator.next() orelse
                    return null,
                // https://httpwg.org/specs/rfc7230.html#whitespace
                " \t",
            );

            var pair_iter = std.mem.splitSequence(u8, pair_string, string_assignment);
            defer std.debug.assert(pair_iter.next() == null);

            const name = try Key.Name.fromString(
                pair_iter.next() orelse
                    return error.UnexpectedEndOfInput,
            );

            const value = pair_iter.next() orelse
                return error.UnexpectedEndOfInput;
            try validateValue(value);

            return .{
                .name = name,
                .value = value,
            };
        }

        pub fn init(string: []const u8) @This() {
            return .{ .pairs_iterator = std.mem.splitSequence(u8, string, string_separator) };
        }
    };

    pub fn fromString(
        allocator: std.mem.Allocator,
        string: []const u8,
    ) (StringIterator.Error || std.mem.Allocator.Error)!@This() {
        var self = @This(){};
        errdefer self.deinit(allocator);

        var iter = StringIterator.init(string);
        while (try iter.next()) |entry|
            try self.entries.put(allocator, .{ .name = entry.name }, entry.value);

        self.reNumber(0);

        return self;
    }

    test fromString {
        var self = try fromString(std.testing.allocator, " \tsimple= simple \t, \ttenant@system=multi_tenant \t");
        defer self.deinit(std.testing.allocator);

        try std.testing.expectEqual(2, self.entries.count());
        try std.testing.expectEqualStrings(" simple", self.entries.get(.{ .name = .{ .simple = "simple" } }).?);
        try std.testing.expectEqualStrings("multi_tenant", self.entries.get(.{ .name = .{ .multi_tenant = .{
            .tenant = "tenant",
            .system = "system",
        } } }).?);

        self.sort();
        var iter = self.entries.iterator();
        try std.testing.expectEqual(.simple, std.meta.activeTag(iter.next().?.key_ptr.name));
        try std.testing.expectEqual(.multi_tenant, std.meta.activeTag(iter.next().?.key_ptr.name));
        try std.testing.expect(iter.next() == null);
    }

    pub fn clone(
        self: @This(),
        allocator: std.mem.Allocator,
        /// Duplicate keys and values?
        dupe: bool,
    ) std.mem.Allocator.Error!@This() {
        if (!dupe) return .{
            .entries = try self.entries.clone(allocator),
        };

        var entries = Entries{};
        errdefer {
            var iter = entries.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.name);
                allocator.free(entry.value_ptr.*);
            }

            entries.deinit(allocator);
        }

        try entries.ensureTotalCapacity(allocator, self.entries.count());

        var iter = entries.iterator();
        while (iter.next()) |entry| {
            const key = Key{
                .position = entry.key_ptr.position,
                .name = try allocator.dupe(u8, entry.key_ptr.name),
            };
            errdefer allocator.free(key.name);

            const value = try allocator.dupe(u8, entry.value_ptr.*);
            errdefer allocator.free(value);

            entries.putAssumeCapacity(key, value);
        }

        return .{ .entries = entries };
    }

    /// Call `sort()` first to get a result that follows the specification!
    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        std.debug.assert(fmt.len == 0);
        try self.toString(writer);
    }

    /// Call `sort()` first to get a result that follows the specification!
    pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
        try write_stream.print("\"{}\"", .{utils.fmt.fmtJsonEncode(self, write_stream.options)});
    }
};

test {
    std.testing.refAllDecls(@This());
}

// TODO run the test suite: https://github.com/w3c/trace-context/tree/main/test

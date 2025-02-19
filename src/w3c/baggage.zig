//! https://www.w3.org/TR/baggage/

const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

/// https://www.w3.org/TR/baggage/#header-name
pub const header_name = "baggage";

pub const string_separator = ",";
pub const string_assignment = "=";

entries: Entries = .{},

pub const Entries = std.StringArrayHashMapUnmanaged(Value);

pub const InvalidEntryError = InvalidKeyError || Value.InvalidError;
pub const InvalidKeyError = error{InvalidBaggageKey};

/// https://www.w3.org/TR/baggage/#value
pub const Value = struct {
    value: []const u8,
    /// https://www.w3.org/TR/baggage/#property
    properties: Properties = .{},

    pub const Properties = std.StringArrayHashMapUnmanaged(?[]const u8);

    pub const string_property_separator = ";";
    pub const string_property_assignment = "=";

    pub const InvalidError = InvalidKeyError || error{InvalidBaggageValue};

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.properties.deinit(allocator);
        self.* = undefined;
    }

    pub fn validate(self: @This()) InvalidError!void {
        try validateValue(self.value);

        var iter = self.properties.iterator();
        while (iter.next()) |entry| {
            try validateKey(entry.key_ptr.*);
            if (entry.value_ptr.*) |value|
                try validateValue(value);
        }
    }

    pub fn validateValue(value: []const u8) InvalidError!void {
        // An empty value is allowed but this might change:
        // https://github.com/w3c/baggage/issues/135
        for (value) |char| switch (char) {
            0x21, 0x23...0x2B, 0x2D...0x3A, 0x3C...0x5B, 0x5D...0x7E => {},
            else => return error.InvalidBaggageValue,
        };
    }

    fn isValidValueChar(char: u8) bool {
        return !std.meta.isError(validateValue(&.{char}));
    }

    pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
        if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
            try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

        try std.Uri.Component.percentEncode(writer, self.value, isValidValueChar);

        var iter = self.properties.iterator();
        while (iter.next()) |entry| {
            try writer.writeAll(string_property_separator);
            try writer.writeAll(entry.key_ptr.*);

            if (entry.value_ptr.*) |value| {
                try writer.writeAll(string_property_assignment);
                try std.Uri.Component.percentEncode(writer, value, isValidValueChar);
            }
        }
    }

    fn percentEncodedValueStringLength(value: []const u8) usize {
        var string_len = value.len;
        for (value) |char| {
            if (isValidValueChar(char)) continue;
            // A percent-encoded character always takes up three bytes like %XX.
            string_len += 2;
        }
        return string_len;
    }

    /// The number of bytes that `toString()` will write.
    pub fn stringLength(self: @This()) usize {
        var string_len = percentEncodedValueStringLength(self.value);

        if (self.properties.count() != 0) {
            var iter = self.properties.iterator();
            while (iter.next()) |entry|
                string_len += propertyKvStringLength(.{ .key = entry.key_ptr.*, .value = entry.value_ptr.* });

            string_len += string_property_separator.len * self.properties.count();
        }

        return string_len;
    }

    pub fn propertyKvStringLength(kv: Properties.KV) usize {
        return kv.key.len + if (kv.value) |value|
            string_property_assignment.len + percentEncodedValueStringLength(value)
        else
            0;
    }

    // TODO percent-encoding
    pub fn fromString(
        allocator: std.mem.Allocator,
        string: []const u8,
    ) (PropertyStringIterator.Error || std.mem.Allocator.Error)!@This() {
        var value_props_iter = std.mem.splitSequence(u8, string, string_property_separator);

        const value = value_props_iter.next() orelse
            return error.UnexpectedEndOfInput;
        try Value.validateValue(value);

        const properties = try propertiesFromString(allocator, value_props_iter.rest());
        errdefer properties.deinit(allocator);

        return .{
            .value = value,
            .properties = properties,
        };
    }

    pub const PropertyStringIterator = struct {
        kv_iterator: KVIterator,

        const KVIterator = KVStringIterator(string_property_separator, string_property_assignment);

        pub const Error = Value.InvalidError || KVIterator.Error;

        pub fn next(self: *@This()) Error!?Properties.KV {
            const kv = try self.kv_iterator.next() orelse
                return null;

            try validateKey(kv.key);

            return .{
                .key = kv.key,
                .value = if (kv.value.len != 0) value: {
                    try validateValue(kv.value);
                    break :value kv.value;
                } else null,
            };
        }

        pub fn init(string: []const u8) @This() {
            return .{ .kv_iterator = KVIterator.init(string) };
        }
    };

    pub fn propertiesFromString(
        allocator: std.mem.Allocator,
        string: []const u8,
    ) (PropertyStringIterator.Error || std.mem.Allocator.Error)!Properties {
        var properties = Properties{};
        errdefer properties.deinit(allocator);

        var props_iter = PropertyStringIterator.init(string);
        while (try props_iter.next()) |kv|
            try properties.put(allocator, kv.key, kv.value);

        return properties;
    }

    pub fn clone(
        self: @This(),
        allocator: std.mem.Allocator,
        dupe: bool,
    ) std.mem.Allocator.Error!@This() {
        if (!dupe) return .{
            .value = self.value,
            .properties = try self.properties.clone(allocator),
        };

        const value = try allocator.dupe(u8, self.value);
        errdefer allocator.free(value);

        var properties = Properties{};
        errdefer {
            var iter = properties.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                if (entry.value_ptr.*) |v|
                    allocator.free(v);
            }

            properties.deinit(allocator);
        }

        try properties.ensureTotalCapacity(allocator, self.properties.count());

        var iter = self.properties.iterator();
        while (iter.next()) |entry| {
            const property_key = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(property_key);

            const property_value = if (entry.value_ptr.*) |v|
                try allocator.dupe(u8, v)
            else
                null;
            errdefer if (property_value) |v| allocator.free(v);

            properties.putAssumeCapacity(property_key, property_value);
        }

        return .{
            .value = value,
            .properties = properties,
        };
    }
};

pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
    for (self.entries.values()) |*value|
        value.deinit(allocator);
    self.entries.deinit(allocator);
    self.* = undefined;
}

/// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
pub fn validateKey(key: []const u8) InvalidKeyError!void {
    if (key.len == 0 or for (key) |char| switch (char) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => break false,
        else => |c| if (std.ascii.isAlphanumeric(c)) break false,
    } else true)
        return error.InvalidBaggageKey;
}

/// https://www.w3.org/TR/baggage/#mutating-baggage
pub fn put(
    self: *@This(),
    allocator: std.mem.Allocator,
    key: []const u8,
    value: Value,
) (InvalidEntryError || std.mem.Allocator.Error)!void {
    try validateKey(key);
    try value.validate();

    try self.entries.put(allocator, key, value);
}

pub const PruneLimits = struct {
    entries: std.math.IntFittingRange(min_entries, max_entries) = max_entries,
    string_len: ?std.math.IntFittingRange(min_string_len, std.math.maxInt(usize)) = null,

    pub const min_entries = 64;
    pub const max_entries = 180;
    pub const min_string_len = 8192;

    pub const InvalidError = error{BaggageLimitsInvalid};

    pub fn valid(self: @This()) @This() {
        return .{
            .entries = @max(min_entries, @min(self.entries, max_entries)),
            .string_len = if (self.string_len) |string_len| @max(min_string_len, string_len) else null,
        };
    }

    pub fn validate(self: @This()) InvalidError!void {
        if (self.entries < min_entries or self.entries > max_entries or
            (if (self.string_len) |string_len| string_len < min_string_len else false))
            return error.BaggageLimitsInvalid;
    }
};

pub const PruneError = error{
    /// The `PruneLimits` remove all entries.
    BaggageLimitsTooAggressive,
} || if (std.debug.runtime_safety) PruneLimits.InvalidError else error{};

/// https://www.w3.org/TR/baggage/#limits
/// Returns the number of entries that were pruned.
pub fn prune(self: *@This(), limits: PruneLimits) PruneError!usize {
    var num_pruned: usize = 0;
    try self.pruneCallback(limits, *usize, error{}, &num_pruned, struct {
        fn call(num_pruned_ptr: *usize, _: Entries.KV) !void {
            num_pruned_ptr.* += 1;
        }
    }.call);
    return num_pruned;
}

/// https://www.w3.org/TR/baggage/#limits
pub fn pruneCallback(
    self: *@This(),
    limits: PruneLimits,
    comptime CallbackCtx: type,
    comptime CallbackError: type,
    callback_ctx: CallbackCtx,
    callback: fn (CallbackCtx, Entries.KV) CallbackError!void,
) (PruneError || CallbackError)!void {
    if (std.debug.runtime_safety and !builtin.is_test)
        try limits.validate();

    var string_len = self.stringLength();
    while (self.entries.count() > limits.entries or
        if (limits.string_len) |msl| string_len > msl else false)
    {
        if (self.entries.count() == 1)
            return error.BaggageLimitsTooAggressive;

        const kv = self.entries.pop();

        string_len -= kvStringLength(kv);
        if (self.entries.count() != 0)
            string_len -= string_separator.len;

        try callback(callback_ctx, kv);
    }
}

pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
    if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
        try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

    var iter = self.entries.iterator();
    while (iter.next()) |entry| {
        if (iter.index != 1) try writer.writeAll(string_separator);
        try writer.writeAll(entry.key_ptr.*);
        try writer.writeAll(string_assignment);
        try entry.value_ptr.toString(writer);
    }
}

// https://www.w3.org/TR/baggage/#example
test toString {
    const allocator = std.testing.allocator;

    var self = @This(){};
    defer self.deinit(allocator);

    try self.entries.put(allocator, "key-1", .{ .value = "value-1" });
    try self.entries.put(allocator, "key-2", .{
        .value = "value-2",
        .properties = try Value.Properties.init(
            allocator,
            &.{ "property-key-1", "property-key-2" },
            &.{ null, "property-value" },
        ),
    });

    try std.testing.expectFmt(
        "key-1=value-1," ++
            "key-2=value-2;" ++
            "property-key-1;" ++
            "property-key-2=property-value",
        "{}",
        .{self},
    );
}

pub fn format(
    self: @This(),
    comptime fmt: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    std.debug.assert(fmt.len == 0);
    try self.toString(writer);
}

pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
    try write_stream.print("\"{}\"", .{utils.fmt.fmtJsonEncode(self, write_stream.options)});
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

pub fn kvStringLength(kv: Entries.KV) usize {
    return kv.key.len +
        string_separator.len +
        kv.value.stringLength();
}

pub const StringIterator = struct {
    kv_iterator: KVIterator,

    const KVIterator = KVStringIterator(string_separator, string_assignment);

    pub const Entry = struct {
        key: []const u8,
        /// Parse using `Value.fromString()`.
        value_with_properties: []const u8,
    };

    pub const Error = InvalidEntryError || KVIterator.Error;

    pub fn next(self: *@This()) Error!?Entry {
        const kv = try self.kv_iterator.next() orelse
            return null;

        try validateKey(kv.key);

        return .{
            .key = kv.key,
            .value_with_properties = kv.value,
        };
    }

    pub fn init(string: []const u8) @This() {
        return .{ .kv_iterator = KVIterator.init(string) };
    }
};

fn KVStringIterator(
    str_separator: []const u8,
    str_assignment: []const u8,
) type {
    return struct {
        pairs_iterator: std.mem.SplitIterator(u8, .sequence),

        pub const Error = error{UnexpectedEndOfInput};

        pub const KV = struct {
            key: []const u8,
            value: []const u8,
        };

        pub fn next(self: *@This()) Error!?KV {
            const pair_string = std.mem.trim(
                u8,
                self.pairs_iterator.next() orelse
                    return null,
                // https://httpwg.org/specs/rfc7230.html#whitespace
                " \t",
            );

            var pair_iter = std.mem.splitSequence(u8, pair_string, str_assignment);

            const key = pair_iter.next() orelse
                return error.UnexpectedEndOfInput;

            return .{
                .key = key,
                // The value may contain `str_property_assignment`:
                // https://www.w3.org/TR/baggage/#value
                .value = pair_iter.rest(),
            };
        }

        pub fn init(string: []const u8) @This() {
            return .{ .pairs_iterator = std.mem.splitSequence(u8, string, str_separator) };
        }
    };
}

pub fn fromString(
    allocator: std.mem.Allocator,
    string: []const u8,
) (StringIterator.Error || std.mem.Allocator.Error)!@This() {
    var self = @This(){};
    errdefer self.deinit(allocator);

    var string_iter = StringIterator.init(string);
    while (try string_iter.next()) |entry| {
        var value = try Value.fromString(allocator, entry.value_with_properties);
        errdefer value.deinit(allocator);

        try self.put(allocator, entry.key, value);
    }

    return self;
}

pub fn clone(
    self: @This(),
    allocator: std.mem.Allocator,
    dupe: bool,
) std.mem.Allocator.Error!@This() {
    if (!dupe) return .{
        .entries = try self.entries.clone(allocator),
    };

    var entries = Entries{};
    errdefer {
        if (dupe) {
            var iter = entries.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.value);
            }
        }

        entries.deinit(allocator);
    }

    try entries.ensureTotalCapacity(allocator, self.entries.count());

    var iter = self.entries.iterator();
    while (iter.next()) |entry| {
        const key = if (dupe) try allocator.dupe(u8, entry.key_ptr.*) else entry.key_ptr.*;
        errdefer if (dupe) allocator.free(key);

        const value = try entry.value_ptr.clone(allocator, dupe);
        errdefer {
            if (dupe) {
                var props_iter = value.properties.iterator();
                while (props_iter.next()) |property| {
                    allocator.free(property.key_ptr.*);
                    if (property.value_ptr.*) |v|
                        allocator.free(v);
                }
            }

            value.deinit();
        }

        entries.putAssumeCapacity(key, value);
    }

    return .{ .entries = entries };
}

test {
    std.testing.refAllDecls(@This());
}

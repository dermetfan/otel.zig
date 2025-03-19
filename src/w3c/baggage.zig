//! https://www.w3.org/TR/baggage/
//!
//! In constrast to the specification,
//! duplicate keys are not allowed.

const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

/// https://www.w3.org/TR/baggage/#header-name
pub const header_name = "baggage";

pub const string_separator = ",";
pub const string_assignment = "=";

/// https://www.w3.org/TR/baggage/#definition
const string_whitespace = " \t";

entries: Entries = .{},

pub const Entries = std.StringArrayHashMapUnmanaged(Value);

pub const InvalidEntryError = InvalidKeyError || Value.InvalidError;
pub const InvalidKeyError = error{InvalidBaggageKey};

/// https://www.w3.org/TR/baggage/#value
pub const Value = struct {
    value: std.Uri.Component,
    /// https://www.w3.org/TR/baggage/#property
    /// Same ownership rules around percent-encoding apply as to `value`.
    properties: Properties = .{},

    pub const Properties = std.StringArrayHashMapUnmanaged(?std.Uri.Component);

    pub const string_property_separator = ";";
    pub const string_property_assignment = "=";

    pub const InvalidError = InvalidKeyError || error{InvalidBaggageValue};

    pub fn deinit(
        self: *@This(),
        allocator: std.mem.Allocator,
        keys_and_values: bool,
    ) void {
        if (keys_and_values)
            deinitValue(allocator, self.value);
        deinitProperties(allocator, &self.properties, keys_and_values);
        self.* = undefined;
    }

    pub fn deinitValue(allocator: std.mem.Allocator, value: std.Uri.Component) void {
        switch (value) {
            inline else => |v| allocator.free(v),
        }
    }

    pub fn deinitProperties(
        allocator: std.mem.Allocator,
        properties: *Properties,
        keys_and_values: bool,
    ) void {
        if (keys_and_values) {
            var iter = properties.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                if (entry.value_ptr.*) |value|
                    deinitValue(allocator, value);
            }
        }

        properties.deinit(allocator);
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

    pub fn validateValue(value: std.Uri.Component) InvalidError!void {
        switch (value) {
            .raw => |string| {
                // An empty value is allowed but this might change:
                // https://github.com/w3c/baggage/issues/135
                for (string) |char|
                    if (!isValidValueChar(char))
                        return error.InvalidBaggageValue;
            },
            .percent_encoded => {},
        }
    }

    fn isValidValueChar(char: u8) bool {
        return switch (char) {
            0x21, 0x23...0x2B, 0x2D...0x3A, 0x3C...0x5B, 0x5D...0x7E => true,
            else => false,
        };
    }

    /// Writes the percent-encoded form.
    fn valueToString(value: std.Uri.Component, writer: anytype) @TypeOf(writer).Error!void {
        switch (value) {
            .raw => |string| try std.Uri.Component.percentEncode(writer, string, isValidValueChar),
            .percent_encoded => |string| try writer.writeAll(string),
        }
    }

    pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
        if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
            try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

        try valueToString(self.value, writer);

        var iter = self.properties.iterator();
        while (iter.next()) |entry| {
            try writer.writeAll(string_property_separator);
            try writer.writeAll(entry.key_ptr.*);

            if (entry.value_ptr.*) |value| {
                try writer.writeAll(string_property_assignment);
                try valueToString(value, writer);
            }
        }
    }

    fn valueStringLength(value: std.Uri.Component) usize {
        switch (value) {
            .raw => |string| {
                var string_len = string.len;
                for (string) |char| {
                    if (isValidValueChar(char)) continue;
                    // A percent-encoded character always takes up three bytes like %XX.
                    string_len += 2;
                }
                return string_len;
            },
            .percent_encoded => |string| return string.len,
        }
    }

    /// The number of bytes that `toString()` will write.
    pub fn stringLength(self: @This()) usize {
        var string_len = valueStringLength(self.value);

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
            string_property_assignment.len + valueStringLength(value)
        else
            0;
    }

    pub fn splitString(string: std.Uri.Component) InvalidError!struct {
        value: std.Uri.Component,
        properties: std.Uri.Component,
    } {
        var value_props_iter = std.mem.splitSequence(u8, switch (string) {
            inline else => |s| s,
        }, string_property_separator);

        const value = switch (string) {
            inline else => |_, tag| @unionInit(
                std.Uri.Component,
                @tagName(tag),
                std.mem.trimRight(u8, value_props_iter.first(), string_whitespace),
            ),
        };
        try validateValue(value);

        return .{
            .value = value,
            .properties = switch (string) {
                inline else => |_, tag| @unionInit(
                    std.Uri.Component,
                    @tagName(tag),
                    std.mem.trimLeft(u8, value_props_iter.rest(), string_whitespace),
                ),
            },
        };
    }

    pub fn fromString(
        allocator: std.mem.Allocator,
        string: std.Uri.Component,
    ) (PropertyStringIterator.Error || std.mem.Allocator.Error)!@This() {
        const split = try splitString(string);

        const properties = try propertiesFromString(allocator, split.properties);
        errdefer properties.deinit(allocator);

        return .{
            .value = split.value,
            .properties = properties,
        };
    }

    pub const PropertyStringIterator = struct {
        kv_iterator: KVIterator,
        input_kind: std.meta.Tag(std.Uri.Component),

        const KVIterator = KVStringIterator(string_property_separator, string_property_assignment);

        pub const Error = InvalidError || KVIterator.Error;

        pub fn next(self: *@This()) Error!?Properties.KV {
            const kv = try self.kv_iterator.next() orelse
                return null;

            const key = std.mem.trimRight(u8, kv.key, string_whitespace);
            try validateKey(key);

            const value = switch (self.input_kind) {
                inline else => |tag| @unionInit(
                    std.Uri.Component,
                    @tagName(tag),
                    std.mem.trimLeft(u8, kv.value, string_whitespace),
                ),
            };
            if (!value.isEmpty())
                try validateValue(value);

            return .{
                .key = key,
                .value = if (value.isEmpty()) null else value,
            };
        }

        pub fn init(string: std.Uri.Component) @This() {
            return .{
                .kv_iterator = KVIterator.init(switch (string) {
                    inline else => |s| s,
                }),
                .input_kind = std.meta.activeTag(string),
            };
        }
    };

    pub fn propertiesFromString(
        allocator: std.mem.Allocator,
        string: std.Uri.Component,
    ) (PropertyStringIterator.Error || std.mem.Allocator.Error)!Properties {
        var properties = Properties{};
        errdefer properties.deinit(allocator);

        var props_iter = PropertyStringIterator.init(string);
        while (try props_iter.next()) |kv|
            try properties.put(allocator, kv.key, kv.value);

        return properties;
    }

    pub const CloneDupeOptions = union(enum) {
        shallow,
        /// See `cloneValue()`.
        /// Applies to all values and property values.
        value_kind: ?std.meta.Tag(std.Uri.Component),
    };

    pub fn clone(
        self: @This(),
        allocator: std.mem.Allocator,
        dupe: CloneDupeOptions,
    ) std.mem.Allocator.Error!@This() {
        switch (dupe) {
            .shallow => return .{
                .value = self.value,
                .properties = try self.properties.clone(allocator),
            },
            .value_kind => |value_kind| {
                const value = try cloneValue(allocator, self.value, value_kind);
                errdefer deinitValue(allocator, value);

                var properties = Properties{};
                errdefer deinitProperties(allocator, &properties, true);

                try properties.ensureTotalCapacity(allocator, self.properties.count());

                var iter = self.properties.iterator();
                while (iter.next()) |entry| {
                    const property_key = try allocator.dupe(u8, entry.key_ptr.*);
                    errdefer allocator.free(property_key);

                    const property_value = if (entry.value_ptr.*) |v| try cloneValue(allocator, v, value_kind) else null;
                    errdefer if (property_value) |v| deinitValue(allocator, v);

                    properties.putAssumeCapacity(property_key, property_value);
                }

                return .{
                    .value = value,
                    .properties = properties,
                };
            },
        }
    }

    pub fn cloneValue(
        allocator: std.mem.Allocator,
        value: std.Uri.Component,
        /// The kind of value to return.
        /// Null means the same as the input.
        value_kind: ?std.meta.Tag(std.Uri.Component),
    ) std.mem.Allocator.Error!std.Uri.Component {
        const actual_kind = if (value_kind) |kind| kind else std.meta.activeTag(value);
        return switch (actual_kind) {
            .raw => .{ .raw = try std.fmt.allocPrint(allocator, "{raw}", .{value}) },
            .percent_encoded => .{
                .percent_encoded = percent_encoded: {
                    const percent_encoded = try allocator.alloc(u8, valueStringLength(value));
                    errdefer allocator.free(percent_encoded);

                    var stream = std.io.fixedBufferStream(percent_encoded);
                    valueToString(value, stream.writer()) catch |err| switch (err) {
                        // We precisely allocated the correct amount of memory using `valueStringLength()`.
                        error.NoSpaceLeft => unreachable,
                    };

                    break :percent_encoded percent_encoded;
                },
            },
        };
    }
};

pub fn deinit(
    self: *@This(),
    allocator: std.mem.Allocator,
    keys_and_values: bool,
) void {
    var iter = self.entries.iterator();
    while (iter.next()) |entry| {
        if (keys_and_values)
            allocator.free(entry.key_ptr.*);
        entry.value_ptr.deinit(allocator, keys_and_values);
    }
    self.entries.deinit(allocator);
    self.* = undefined;
}

/// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
pub fn validateKey(key: []const u8) InvalidKeyError!void {
    if (key.len == 0 or for (key) |char| switch (char) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
        else => |c| if (!std.ascii.isAlphanumeric(c)) break true,
    } else false)
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

        const kv = self.entries.pop().?;

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

test toString {
    const allocator = std.testing.allocator;

    var self = @This(){};
    defer self.deinit(allocator, false);

    try self.entries.put(allocator, "key-1", .{ .value = .{ .raw = "value-1" } });
    try self.entries.put(allocator, "key-2", .{
        .value = .{ .percent_encoded = "value-2" },
        .properties = try Value.Properties.init(
            allocator,
            &.{ "property-key-1", "property-key-2" },
            &.{ null, .{ .raw = "property-value" } },
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
        /// Parse using `Value.fromString()` or split with `Value.splitString()`.
        value_with_properties: []const u8,
    };

    pub const Error = InvalidEntryError || KVIterator.Error;

    pub fn next(self: *@This()) Error!?Entry {
        const kv = try self.kv_iterator.next() orelse
            return null;

        const key = std.mem.trimRight(u8, kv.key, string_whitespace);
        try validateKey(key);

        return .{
            .key = key,
            .value_with_properties = std.mem.trimLeft(u8, kv.value, string_whitespace),
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
                string_whitespace,
            );

            // When the input is an empty string,
            // the first call to `self.pairs_iterator.next()`
            // returns an empty string instead of `null`.
            if (pair_string.len == 0)
                return null;

            var pair_iter = std.mem.splitSequence(u8, pair_string, str_assignment);

            const key = pair_iter.next() orelse
                return error.UnexpectedEndOfInput;

            return .{
                .key = key,
                // The value may contain `str_assignment`:
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
    string: std.Uri.Component,
) (StringIterator.Error || std.mem.Allocator.Error)!@This() {
    var self = @This(){};
    errdefer self.deinit(allocator, false);

    var string_iter = StringIterator.init(switch (string) {
        inline else => |s| s,
    });
    while (try string_iter.next()) |entry| {
        var value = try Value.fromString(allocator, switch (string) {
            inline else => |_, tag| @unionInit(
                std.Uri.Component,
                @tagName(tag),
                entry.value_with_properties,
            ),
        });
        errdefer value.deinit(allocator, false);

        try self.entries.put(allocator, entry.key, value);
    }

    return self;
}

test fromString {
    var self = try fromString(
        std.testing.allocator,
        std.Uri.Component{
            .raw = "key-1=value-1," ++
                "key-2 = value-2 ;" ++
                "property-key-1 \t;\t " ++
                "property-key-2 = property-value",
        },
    );
    defer self.deinit(std.testing.allocator, false);

    try std.testing.expectEqual(2, self.entries.count());
    {
        const value = self.entries.get("key-1").?;
        try std.testing.expectEqualDeep(std.Uri.Component{ .raw = "value-1" }, value.value);
        try std.testing.expectEqual(0, value.properties.count());
    }
    {
        const value = self.entries.get("key-2").?;
        try std.testing.expectEqualDeep(std.Uri.Component{ .raw = "value-2" }, value.value);
        try std.testing.expectEqual(2, value.properties.count());
        try std.testing.expectEqualDeep(null, value.properties.get("property-key-1").?);
        try std.testing.expectEqualDeep(std.Uri.Component{ .raw = "property-value" }, value.properties.get("property-key-2").?);
    }
}

pub fn clone(
    self: @This(),
    allocator: std.mem.Allocator,
    dupe: Value.CloneDupeOptions,
) std.mem.Allocator.Error!@This() {
    var copy = @This(){};
    errdefer copy.deinit(allocator, dupe != .shallow);

    try copy.entries.ensureTotalCapacity(allocator, self.entries.count());

    var iter = self.entries.iterator();
    while (iter.next()) |entry| {
        const key = if (dupe != .shallow) try allocator.dupe(u8, entry.key_ptr.*) else entry.key_ptr.*;
        errdefer if (dupe != .shallow) allocator.free(key);

        const value = try entry.value_ptr.clone(allocator, dupe);
        errdefer value.deinit(dupe != .shallow);

        copy.entries.putAssumeCapacity(key, value);
    }

    return copy;
}

test {
    std.testing.refAllDecls(@This());
}

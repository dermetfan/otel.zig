const std = @import("std");
const utils = @import("utils");

// pub const context = @import("api/context.zig");
pub const trace = @import("api/trace.zig");

/// https://opentelemetry.io/docs/specs/otel/common/#attribute
pub const Attributes = struct {
    map: Map = .{},

    pub const Map = std.ArrayHashMapUnmanaged([]const u8, Value, struct {
        pub fn hash(_: @This(), key: []const u8) u32 {
            return @truncate(std.hash_map.hashString(key));
        }

        pub fn eql(_: @This(), a: []const u8, b: []const u8, _: usize) bool {
            return std.hash_map.eqlString(a, b);
        }
    }, false);

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.map.deinit(allocator);
        self.* = undefined;
    }

    pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
        try write_stream.beginObject();

        var iter = self.map.iterator();
        while (iter.next()) |attribute| {
            try write_stream.objectField(attribute.key_ptr.*);
            try write_stream.write(attribute.value_ptr.*);
        }

        try write_stream.endObject();
    }

    pub const Value = union(enum) {
        one: Primitive,
        many: utils.meta.MapFields(Primitive, struct {
            fn map(field: utils.meta.FieldInfo(Primitive)) utils.meta.FieldInfo(Primitive) {
                var f = field;
                // XXX Would it be better if this was just a slice?
                f.type = std.ArrayListUnmanaged(field.type);
                return f;
            }
        }.map),

        pub const Primitive = union(enum) {
            string: []const u8,
            bool: bool,
            float: f64,
            int: i64,
        };

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            switch (self) {
                .one => |one| try write_stream.write(one),
                .many => |many| switch (many) {
                    inline else => |primitives| {
                        try write_stream.beginArray();
                        for (primitives.items) |primitive|
                            try write_stream.write(primitive);
                        try write_stream.endArray();
                    },
                },
            }
        }
    };
};

/// https://opentelemetry.io/docs/specs/otel/glossary/#instrumentation-scope
pub const InstrumentationScope = struct {
    name: []const u8,
    version: ?std.SemanticVersion = null,
    schema_url: ?std.Uri = null,
    attributes: Attributes = .{},

    pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
        try write_stream.beginObject();

        try write_stream.objectField("name");
        try write_stream.write(self.name);

        try write_stream.objectField("version");
        if (self.version) |version|
            try write_stream.print("\"{}\"", .{utils.fmt.fmtJsonEncode(version, write_stream.options)})
        else
            try write_stream.write(null);

        try write_stream.objectField("schema_url");
        if (self.schema_url) |schema_url|
            try write_stream.print("\"{}\"", .{utils.fmt.fmtJsonEncode(schema_url, write_stream.options)})
        else
            try write_stream.write(null);

        try write_stream.objectField("attributes");
        try write_stream.write(self.attributes);

        try write_stream.endObject();
    }
};

test {
    std.testing.refAllDecls(@This());
}

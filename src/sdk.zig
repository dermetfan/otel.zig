const std = @import("std");
const protobuf = @import("protobuf");

const api = @import("api");
const otlp = @import("otlp");

// pub const context = @import("sdk/context.zig");
pub const trace = @import("sdk/trace.zig");

pub const Resource = @import("sdk/Resource.zig");

pub const to_otlp = struct {
    pub fn attributes(allocator: std.mem.Allocator, attrs: api.Attributes, dupe: bool) std.mem.Allocator.Error!otlp.common.KeyValueList {
        var kvs = otlp.common.KeyValueList{ .values = try std.ArrayList(otlp.common.KeyValue).initCapacity(allocator, attrs.count()) };
        errdefer kvs.deinit();

        var attributes_iter = attrs.iterator();
        while (attributes_iter.next()) |attribute|
            kvs.values.appendAssumeCapacity(.{
                .key = if (dupe)
                    try protobuf.ManagedString.copy(attribute.key_ptr.*, allocator)
                else
                    protobuf.ManagedString.managed(attribute.key_ptr.*),
                .value = try attributeValue(allocator, attribute.value_ptr.*, dupe),
            });

        return kvs;
    }

    pub fn attributeValue(allocator: std.mem.Allocator, attribute_value: api.AttributeValue, dupe: bool) std.mem.Allocator.Error!otlp.common.AnyValue {
        return .{
            .value = switch (attribute_value) {
                .one => |primitive| switch (primitive) {
                    .string => |value| value: {
                        const managed_value = if (dupe)
                            try protobuf.ManagedString.copy(value, allocator)
                        else
                            protobuf.ManagedString.managed(value);
                        break :value if (std.unicode.utf8ValidateSlice(value))
                            .{ .string_value = managed_value }
                        else
                            .{ .bytes_value = managed_value };
                    },
                    .bool => |value| .{ .bool_value = value },
                    .float => |value| .{ .double_value = value },
                    .int => |value| .{ .int_value = value },
                },
                .many => |many| switch (many) {
                    inline else => |primitives, tag| case: {
                        var array = otlp.common.ArrayValue{
                            .values = try std.ArrayList(otlp.common.AnyValue).initCapacity(allocator, primitives.items.len),
                        };
                        errdefer array.deinit();

                        for (primitives.items) |primitive|
                            array.values.appendAssumeCapacity(
                                try attributeValue(allocator, .{
                                    .one = @unionInit(
                                        api.AttributeValue.Primitive,
                                        @tagName(tag),
                                        primitive,
                                    ),
                                }, dupe),
                            );

                        break :case .{ .array_value = array };
                    },
                },
            },
        };
    }

    pub fn instrumentationScope(
        allocator: std.mem.Allocator,
        scope: api.InstrumentationScope,
        dupe: bool,
    ) std.mem.Allocator.Error!otlp.common.InstrumentationScope {
        const name = if (dupe)
            try protobuf.ManagedString.copy(scope.name, allocator)
        else
            protobuf.ManagedString.managed(scope.name);
        errdefer name.deinit();

        const version = if (scope.version) |version|
            protobuf.ManagedString.move(
                try std.fmt.allocPrint(allocator, "{}", .{version}),
                allocator,
            )
        else
            .Empty;
        errdefer version.deinit();

        // It is correct that this is unused.
        // When converting to the protobuf types,
        // a field for the schema URL exist elsewhere,
        // for example on `otlp.trace.ScopeSpans`.
        _ = scope.schema_url;

        const attrs = try attributes(allocator, scope.attributes, dupe);
        errdefer attrs.deinit();

        return .{
            .name = name,
            .version = version,
            .attributes = attrs.values,
            .dropped_attributes_count = 0,
        };
    }
};

test {
    std.testing.refAllDecls(@This());
}

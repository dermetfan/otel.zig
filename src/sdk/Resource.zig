const builtin = @import("builtin");
const std = @import("std");
const protobuf = @import("protobuf");

const api = @import("api");
const otlp = @import("otlp");

const sdk = @import("../sdk.zig");

attributes: api.Attributes = .{},
schema_url: ?std.Uri = null,

/// https://opentelemetry.io/docs/specs/otel/resource/sdk/#sdk-provided-resource-attributes
pub fn default(allocator: std.mem.Allocator, service_name: []const u8) std.mem.Allocator.Error!@This() {
    return .{
        .attributes = .{
            .map = try api.Attributes.Map.init(
                allocator,
                &.{
                    "service.name",
                    "telemetry.sdk.language",
                    "telemetry.sdk.name",
                    "telemetry.sdk.version",
                },
                &.{
                    .{ .one = .{ .string = service_name } },
                    .{ .one = .{ .string = "zig" } },
                    .{ .one = .{ .string = "opentelemetry" } },
                    // XXX do this once the compiler supports it
                    // @import("../../../build.zig.zon").version
                    .{ .one = .{ .string = "0.0.0" } },
                },
            ),
        },
    };
}

/// https://opentelemetry.io/docs/specs/otel/resource/sdk/#merge
pub fn merge(self: *@This(), allocator: std.mem.Allocator, updating: @This()) (std.mem.Allocator.Error || error{ConflictingSchemas})!void {
    if (updating.schema_url) |schema_url| {
        if (self.schema_url) |_|
            return error.ConflictingSchemas;

        self.schema_url = schema_url;
    }

    var iter = updating.attributes.iterator();
    while (iter.next()) |entry|
        try self.attributes.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
}

pub fn toOtlp(
    self: @This(),
    allocator: std.mem.Allocator,
    dupe: bool,
) std.mem.Allocator.Error!otlp.resource.Resource {
    const attrs = try sdk.to_otlp.attributes(allocator, self.attributes, dupe);
    errdefer attrs.deinit();

    // It is correct that this is unused.
    // When converting to the protobuf types,
    // a field for the schema URL exist elsewhere,
    // for example on `otlp.trace.ResourceSpans`.
    _ = self.schema_url;

    return .{
        .attributes = attrs.values,
        .dropped_attributes_count = 0,
    };
}

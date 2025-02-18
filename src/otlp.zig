//! This file is the root of the `otlp` module set up in `build.zig`
//! and is copied into a cache directory alongside the generated protobuf types
//! and can therefore not import other files in `src` by relative path.

const std = @import("std");
const utils = @import("utils");
const retry = @import("retry");

pub const collector = struct {
    pub const trace = @import("opentelemetry/proto/collector/trace/v1.pb.zig");
};
pub const common = struct {
    pub usingnamespace @import("opentelemetry/proto/common/v1.pb.zig");

    /// `jsonStringify()` implementations for OTLP types.
    /// https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding
    pub const json_stringify = struct {
        pub fn keyValueList(key_value_list: common.KeyValueList, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("values");
            try write_stream.beginArray();
            for (key_value_list.values.items) |key_value|
                try keyValue(key_value, write_stream);
            try write_stream.endArray();

            try write_stream.endObject();
        }

        pub fn keyValue(key_value: common.KeyValue, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("key");
            try write_stream.write(key_value.key);

            try write_stream.objectField("value");
            try anyValue(key_value.value.?, write_stream);

            try write_stream.endObject();
        }

        pub fn anyValue(any_value: common.AnyValue, write_stream: anytype) utils.meta.ChildOrelseSelf(@TypeOf(write_stream)).Error!void {
            if (any_value.value) |avv| {
                try write_stream.beginObject();

                try write_stream.objectField(switch (avv) {
                    .bool_value => "boolValue",
                    .int_value => "intValue",
                    .double_value => "doubleValue",
                    .string_value => "stringValue",
                    .bytes_value => "bytesValue",
                    .array_value => "arrayValue",
                    .kvlist_value => "kvlistValue",
                });
                try switch (avv) {
                    inline .bool_value,
                    .int_value,
                    .double_value,
                    .string_value,
                    .bytes_value,
                    => |v| write_stream.write(v),
                    .array_value => |v| arrayValue(v, write_stream),
                    .kvlist_value => |v| keyValueList(v, write_stream),
                };

                try write_stream.endObject();
            } else try write_stream.write(null);
        }

        pub fn arrayValue(array_value: common.ArrayValue, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("values");
            try write_stream.beginArray();
            for (array_value.values.items) |v|
                try anyValue(v, write_stream);
            try write_stream.endArray();

            try write_stream.endObject();
        }

        pub fn instrumentationScope(instrumentation_scope: common.InstrumentationScope, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("name");
            try write_stream.write(instrumentation_scope.name);

            try write_stream.objectField("version");
            try write_stream.write(instrumentation_scope.version);

            try write_stream.objectField("attributes");
            try write_stream.beginArray();
            for (instrumentation_scope.attributes.items) |attribute|
                try keyValue(attribute, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("droppedAttributesCount");
            try write_stream.write(instrumentation_scope.dropped_attributes_count);

            try write_stream.endObject();
        }
    };
};
pub const resource = struct {
    pub usingnamespace @import("opentelemetry/proto/resource/v1.pb.zig");

    pub fn jsonStringify(otlp_resource: resource.Resource, write_stream: anytype) !void {
        try write_stream.beginObject();

        try write_stream.objectField("attributes");
        try write_stream.beginArray();
        for (otlp_resource.attributes.items) |attribute|
            try common.json_stringify.keyValue(attribute, write_stream);
        try write_stream.endArray();

        try write_stream.objectField("droppedAttributesCount");
        try write_stream.write(otlp_resource.dropped_attributes_count);

        try write_stream.endObject();
    }
};
pub const trace = struct {
    pub usingnamespace @import("opentelemetry/proto/trace/v1.pb.zig");

    /// `jsonStringify()` implementations for OTLP types.
    /// https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding
    pub const json_stringify = struct {
        pub fn resourceSpans(resource_spans: trace.ResourceSpans, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("schemaUrl");
            try write_stream.write(resource_spans.schema_url);

            try write_stream.objectField("resource");
            if (resource_spans.resource) |otlp_resource|
                try resource.jsonStringify(otlp_resource, write_stream)
            else
                try write_stream.write(null);

            try write_stream.objectField("scopeSpans");
            try write_stream.beginArray();
            for (resource_spans.scope_spans.items) |scope_spans|
                try scopeSpans(scope_spans, write_stream);
            try write_stream.endArray();

            try write_stream.endObject();
        }

        pub fn scopeSpans(scope_spans: trace.ScopeSpans, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("scope");
            if (scope_spans.scope) |scope|
                try common.json_stringify.instrumentationScope(scope, write_stream)
            else
                try write_stream.write(null);

            try write_stream.objectField("spans");
            try write_stream.beginArray();
            for (scope_spans.spans.items) |otlp_span|
                try span(otlp_span, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("schemaUrl");
            try write_stream.write(scope_spans.schema_url);

            try write_stream.endObject();
        }

        pub fn span(otlp_span: trace.Span, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("traceId");
            try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(otlp_span.trace_id.getSlice())});

            try write_stream.objectField("spanId");
            try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(otlp_span.span_id.getSlice())});

            try write_stream.objectField("traceState");
            try write_stream.write(otlp_span.trace_state);

            try write_stream.objectField("parentSpanId");
            try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(otlp_span.parent_span_id.getSlice())});

            try write_stream.objectField("flags");
            try write_stream.write(otlp_span.flags);

            try write_stream.objectField("name");
            try write_stream.write(otlp_span.name);

            try write_stream.objectField("kind");
            try write_stream.write(@intFromEnum(otlp_span.kind));

            try write_stream.objectField("startTimeUnixNano");
            try write_stream.write(otlp_span.start_time_unix_nano);

            try write_stream.objectField("endTimeUnixNano");
            try write_stream.write(otlp_span.end_time_unix_nano);

            try write_stream.objectField("attributes");
            try write_stream.beginArray();
            for (otlp_span.attributes.items) |attribute|
                try common.json_stringify.keyValue(attribute, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("droppedAttributesCount");
            try write_stream.write(otlp_span.dropped_attributes_count);

            try write_stream.objectField("events");
            try write_stream.beginArray();
            for (otlp_span.events.items) |event|
                try spanEvent(event, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("droppedEventsCount");
            try write_stream.write(otlp_span.dropped_events_count);

            try write_stream.objectField("links");
            try write_stream.beginArray();
            for (otlp_span.links.items) |link|
                try spanLink(link, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("droppedLinksCount");
            try write_stream.write(otlp_span.dropped_links_count);

            try write_stream.objectField("status");
            try spanStatus(otlp_span.status orelse .{}, write_stream);

            try write_stream.endObject();
        }

        pub fn spanEvent(event: trace.Span.Event, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("timeUnixNano");
            try write_stream.write(event.time_unix_nano);

            try write_stream.objectField("name");
            try write_stream.write(event.name);

            try write_stream.objectField("attributes");
            try write_stream.beginArray();
            for (event.attributes.items) |attribute|
                try common.json_stringify.keyValue(attribute, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("droppedAttributesCount");
            try write_stream.write(event.dropped_attributes_count);

            try write_stream.endObject();
        }

        pub fn spanLink(link: trace.Span.Link, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("traceId");
            try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(link.trace_id.getSlice())});

            try write_stream.objectField("spanId");
            try write_stream.print("\"{}\"", .{std.fmt.fmtSliceHexLower(link.span_id.getSlice())});

            try write_stream.objectField("traceState");
            try write_stream.write(link.trace_state);

            try write_stream.objectField("attributes");
            try write_stream.beginArray();
            for (link.attributes.items) |attribute|
                try common.json_stringify.keyValue(attribute, write_stream);
            try write_stream.endArray();

            try write_stream.objectField("droppedAttributesCount");
            try write_stream.write(link.dropped_attributes_count);

            try write_stream.objectField("flags");
            try write_stream.write(link.flags);

            try write_stream.endObject();
        }

        pub fn spanStatus(status: trace.Status, write_stream: anytype) !void {
            try write_stream.beginObject();

            try write_stream.objectField("code");
            try write_stream.write(@intFromEnum(status.code));

            try write_stream.objectField("message");
            try write_stream.write(status.message);

            try write_stream.endObject();
        }
    };
};

/// The OTLP specification makes use of types from Google's APIs.
pub const rpc = @import("google/rpc.pb.zig");

/// https://opentelemetry.io/docs/specs/otel/protocol/exporter/
pub const Exporter = struct {
    endpoint: std.Uri,
    insecure: bool = false,
    // TODO `cert_file`, `client_key_file`, `client_cert_file`
    headers: []const std.http.Header = &.{},
    compression: ?enum { gzip } = null,
    timeout_ms: ?u64 = null,
    protocol: union(enum) {
        grpc: void, // TODO
        http_protobuf: std.http.Client,
        http_json: std.http.Client,
    },
    /// https://opentelemetry.io/docs/specs/otel/protocol/exporter/#retry
    retry_policy: retry.Policy = .{},

    pub fn deinit(self: *@This()) void {
        switch (self.protocol) {
            .grpc => unreachable, // TODO not yet implemented
            .http_protobuf, .http_json => |*client| client.deinit(),
        }
    }

    // XXX get version from `build.zig.zon` once the compiler supports that
    const user_agent = "OTel-OTLP-Exporter-Zig/0.0.0";

    pub const ExportError = ExportHttpError;
    pub const ExportHttpError =
        std.time.Timer.Error ||
        ParseHttpResponseBodyError ||
        std.http.Client.Request.WaitError ||
        std.http.Client.Request.FinishError ||
        std.compress.flate.Compressor(std.http.Client.Request.Writer).Writer.Error ||
        error{ ClientError, ServerError };

    pub const Signal = enum {
        traces,

        fn Request(self: @This()) type {
            return switch (self) {
                .traces => collector.trace.ExportTraceServiceRequest,
            };
        }

        fn Response(self: @This()) type {
            return switch (self) {
                .traces => collector.trace.ExportTraceServiceResponse,
            };
        }
    };

    pub fn @"export"(
        self: *@This(),
        allocator: std.mem.Allocator,
        comptime S: Signal,
        signal: S.Request(),
        timeout_ms: ?u32,
        diagnostics: ?*rpc.Status,
    ) ExportError!S.Response() {
        return switch (self.protocol) {
            .http_protobuf, .http_json => self.exportHttp(allocator, S, signal, timeout_ms, diagnostics),
            .grpc => unreachable, // TODO not yet implemented
        };
    }

    fn exportHttp(
        self: *@This(),
        allocator: std.mem.Allocator,
        comptime S: Signal,
        signal: S.Request(),
        timeout_ms: ?u32,
        /// Will only be valid when one of `error{ClientError, ServerError}` is returned!
        diagnostics: ?*rpc.Status,
    ) ExportHttpError!S.Response() {
        var timer = if (timeout_ms != null)
            try std.time.Timer.start()
        else
            null;

        const client = switch (self.protocol) {
            else => unreachable,
            .http_protobuf, .http_json => |*client| client,
        };

        var extra_headers = std.ArrayListUnmanaged(std.http.Header){};
        defer extra_headers.deinit(allocator);

        try extra_headers.appendSlice(allocator, self.headers);
        if (self.compression) |compression|
            try extra_headers.append(allocator, .{
                .name = "Content-Encoding",
                .value = @tagName(compression),
            });

        var backoffs = self.retry_policy.backoffs();
        retry: while (true) {
            var request = try client.open(.POST, self.endpoint, .{
                .server_header_buffer = server_header_buffer: {
                    var buffer: [16 * utils.mem.b_per_kib]u8 = undefined;
                    break :server_header_buffer &buffer;
                },
                .headers = .{
                    .user_agent = .{ .override = user_agent },
                    .content_type = switch (self.protocol) {
                        else => unreachable,
                        .http_protobuf => .{ .override = "application/x-protobuf" },
                        .http_json => .{ .override = "application/json" },
                    },
                },
                .extra_headers = extra_headers.items,
            });
            defer request.deinit();

            request.transfer_encoding = .chunked;

            try request.send();

            // Unfortunately we cannot write directly into `request.writer()`
            // because zig-protobuf can only write to `ArrayList(u8).Writer`
            // because it needs to allocate to base64-encode strings.
            // XXX Zig 0.14.0 added `std.base64.Base64Encoder.encodeWriter()`
            // which could be used to fix this in zig-protobuf. Open PR?
            if (true) {
                var body_str = std.ArrayList(u8).init(allocator);
                defer body_str.deinit();

                switch (self.protocol) {
                    else => unreachable,
                    .http_protobuf => {
                        const signal_encoded = try signal.encode(allocator);
                        defer allocator.free(signal_encoded);

                        try body_str.appendSlice(signal_encoded);
                    },
                    .http_json => try std.json.stringify(signal, .{}, body_str.writer()),
                }

                if (self.compression) |compression| {
                    var body_str_stream = std.io.fixedBufferStream(body_str.items);
                    switch (compression) {
                        .gzip => try std.compress.gzip.compress(body_str_stream.reader(), request.writer(), .{}),
                    }
                } else try request.writer().writeAll(body_str.items);
            } else {
                var body_compressor = if (self.compression) |compression|
                    switch (compression) {
                        .gzip => try std.compress.gzip.compressor(request.writer(), .{}),
                    }
                else
                    null;

                const body_writer: union(enum) {
                    compress: @typeInfo(@TypeOf(body_compressor)).Optional.child.Writer,
                    raw: std.http.Client.Request.Writer,
                } = if (body_compressor) |*compressor|
                    .{ .compress = compressor.writer() }
                else
                    .{ .raw = request.writer() };

                switch (self.protocol) {
                    else => unreachable,
                    .http_protobuf => {
                        const body_str = try signal.encode(allocator);
                        defer allocator.free(body_str);

                        switch (body_writer) {
                            inline else => |writer| try writer.writeAll(body_str),
                        }
                    },
                    .http_json => switch (body_writer) {
                        inline else => |writer| try std.json.stringify(signal, .{}, writer),
                    },
                }

                if (body_compressor) |*compressor|
                    try compressor.finish();
            }
            try request.finish();

            try request.wait();
            switch (request.response.status.class()) {
                inline .client_error, .server_error => |class| {
                    switch (request.response.status) {
                        .too_many_requests, .bad_gateway, .service_unavailable, .gateway_timeout => if (backoffs.next()) |backoff_ns| {
                            var headers_iter = request.response.iterateHeaders();
                            const retry_after_s = retry_after_s: while (headers_iter.next()) |header| {
                                if (!std.ascii.eqlIgnoreCase(header.name, "Retry-After")) continue;

                                // The spec reads like only a number of seconds is allowed,
                                // not an HTTP date as is also allowed by the HTTP spec.
                                break :retry_after_s std.fmt.parseUnsigned(u64, header.value, 10) catch continue;
                            } else null;

                            const delay_ns = if (retry_after_s) |ras|
                                ras * std.time.ns_per_s
                            else
                                backoff_ns;

                            const do_retry = if (timeout_ms) |t_ms|
                                delay_ns <= remaining_ns: {
                                    break :remaining_ns t_ms * std.time.ns_per_ms -| timer.?.read();
                                }
                            else
                                true;

                            if (do_retry) {
                                std.time.sleep(delay_ns);
                                continue :retry;
                            }
                        },
                        else => {},
                    }

                    if (diagnostics) |d|
                        d.* = try parseHttpResponseBody(rpc.Status, allocator, &request, .{});

                    return switch (class) {
                        else => comptime unreachable,
                        .client_error => error.ClientError,
                        .server_error => error.ServerError,
                    };
                },
                else => return try parseHttpResponseBody(S.Response(), allocator, &request, .{}),
            }
        }
    }

    const ParseHttpResponseBodyError =
        // Unfortunately `@import("protobuf").DecodingError` is not public.
        error{ NotEnoughData, InvalidInput } ||
        std.json.ParseError(std.json.Reader(std.json.default_buffer_size, std.http.Client.Request.Reader)) ||
        error{
        // Unfortunately `std.io.Reader.readAllAlloc()` does not expose a named error set.
        StreamTooLong,

        UnsupportedContentType,
        NoContentType,
    };

    fn parseHttpResponseBody(
        /// A protobuf type.
        comptime T: type,
        allocator: std.mem.Allocator,
        request: *std.http.Client.Request,
        options: struct {
            /// Memory limit in case of binary protobuf body.
            max_body_size_b: usize = utils.mem.b_per_gib,
        },
    ) !T {
        if (request.response.content_type) |content_type| {
            if (std.ascii.eqlIgnoreCase(content_type, "application/x-protobuf")) {
                const body = try request.reader().readAllAlloc(allocator, options.max_body_size_b);
                defer allocator.free(body);

                return try T.decode(body, allocator);
            }

            if (std.ascii.eqlIgnoreCase(content_type, "application/json")) {
                var reader = std.json.reader(allocator, request.reader());
                return try std.json.parseFromTokenSourceLeaky(T, allocator, &reader, .{
                    .ignore_unknown_fields = true,
                    .allocate = .alloc_always,
                });
            }

            return error.UnsupportedContentType;
        } else return error.NoContentType;
    }
};

test {
    std.testing.refAllDecls(@This());
}

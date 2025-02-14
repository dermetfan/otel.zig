const std = @import("std");
const utils = @import("utils");
const w3c_trace_context = @import("w3c-trace-context");

const api = @import("../api.zig");

const trace = @This();

/// https://opentelemetry.io/docs/specs/otel/trace/api/#tracerprovider
pub fn TracerProvider(comptime Impl: type) type {
    return struct {
        comptime {
            _ = std.testing.refAllDecls(trace.Tracer(@This().Tracer));
        }

        impl: Impl,

        pub const Tracer = utils.meta.ChildOrelseSelf(Impl).Tracer;

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#get-a-tracer
        pub fn tracer(
            self: utils.meta.LikeReceiver(Impl, .tracer, @This()),
            /// Scopes are compared by their pointer
            /// so do not pass in pointers to multiple identical instances!
            /// This is relied upon by the span processor to separate batches.
            /// However, the worst that can happen is inefficency
            /// in runtime performance and data emitted by the exporter
            /// due to unnecessarily many calls to the export function
            /// with separate batches that could have been one.
            id: *const api.InstrumentationScope,
        ) @This().Tracer {
            return self.impl.tracer(id);
        }

        // pub inline fn any(self: *@This()) AnyTracerProvider {
        //     return .{
        //         .context = self,
        //         .tracerFn = typeErasedTracerFn,
        //     };
        // }

        // fn typeErasedTracerFn(self: *@This(), id: InstrumentationScope) AnyTracer {
        //     return self.tracer(id).any();

        //     // TODO interfaces that support both static and dynamic dispatch
        //     // have `@import("root").otel_options.TracerProvider: type`
        //     // that is set by the sdk consumer and could as well be AnyTracerProvider
        //     // provide both generic types and any types for everything
        //     // in functions, take anytype to make it comfortable but check the given type using `fn(foo: anytype) { _ = TracerProvider(@TypeOf(foo)); }`?
        //     // (in Impl types, could check using `comptime _ = TracerProvider(@This());` but we could omit that by having `.tracerProvider()` like we do currently)
        // }
    };
}

// pub const AnyTracerProvider = struct {
//     context: *anyopaque,
//     tracerFn: *const fn (*anyopaque, InstrumentationScope) @This().Tracer,

//     pub const Tracer = AnyTracer;

//     pub fn tracer(self: *@This(), id: InstrumentationScope) @This().Tracer {
//         return self.tracerFn(self.context, id);
//     }
// };

/// https://opentelemetry.io/docs/specs/otel/trace/api/#tracer
pub fn Tracer(comptime Impl: type) type {
    return struct {
        comptime {
            _ = std.testing.refAllDecls(trace.Span(@This().Span));
        }

        impl: Impl,

        pub const Span = utils.meta.ChildOrelseSelf(Impl).Span;

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#span-creation
        pub fn span(
            self: utils.meta.LikeReceiver(Impl, .span, @This()),
            /// Backing allocator must stay alive until
            /// the span processor is done and calls `Span.deinit()`.
            arena: std.heap.ArenaAllocator,
            /// Must outlive this span just like `arena`'s backing allocator.
            name: []const u8,
            /// Any allocations backing this must reside in `arena`.
            options: SpanCreationOptions,
        ) !@This().Span {
            return try self.impl.span(arena, name, options);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#enabled
        pub fn enabled(self: @This()) bool {
            return self.impl.enabled();
        }

        // pub inline fn any(self: *@This()) AnyTracer {
        //     return .{
        //         .context = self,
        //         .spanFn = typeErasedSpanFn,
        //         .enabledFn = typeErasedEnabledFn,
        //     };
        // }

        // fn typeErasedSpanFn(
        //     context: *anyopaque,
        //     arena: std.heap.ArenaAllocator,
        //     name: []const u8,
        //     options: SpanCreationOptions,
        // ) std.mem.Allocator.Error!AnySpan {
        //     const self: *@This() = @alignCast(@ptrCast(context));
        //     return self.span(arena, name, options).any();
        // }

        // fn typeErasedEnabledFn(context: *const anyopaque) bool {
        //     const self: *const @This() = @alignCast(@ptrCast(context));
        //     return self.enabled();
        // }
    };
}

// pub const AnyTracer = struct {
//     context: *anyopaque,
//     spanFn: *const fn (*anyopaque, std.heap.ArenaAllocator, []const u8, SpanCreationOptions) std.mem.Allocator.Error!@This().Span,
//     enabledFn: *const fn (*const anyopaque) bool,

//     pub const Span = AnySpan;

//     pub fn span(self: *@This(), allocator: std.heap.ArenaAllocator, name: []const u8, options: SpanCreationOptions) std.mem.Allocator.Error!@This().Span {
//         return self.spanFn(self.context, allocator, name, options);
//     }

//     pub fn enabled(self: @This()) bool {
//         return self.enabledFn(self.context);
//     }
// };

/// https://opentelemetry.io/docs/specs/otel/trace/api/#span-creation
pub const SpanCreationOptions = struct {
    parent: ?SpanContext = null,
    kind: SpanKind = .internal,
    attributes: api.Attributes = .{},
    links: std.ArrayListUnmanaged(SpanLink) = .{},
    start_ns: ?i128 = null,
};

/// https://opentelemetry.io/docs/specs/otel/trace/api/#behavior-of-the-api-in-the-absence-of-an-installed-sdk
pub const NoopTracerProvider = struct {
    pub const TracerProvider = trace.TracerProvider(@This());

    pub fn tracerProvider(self: @This()) @This().TracerProvider {
        return .{ .impl = self };
    }

    pub const Tracer = NoopTracer;

    pub fn tracer(_: @This(), _: *const api.InstrumentationScope) NoopTracer {
        return .{};
    }
};

/// https://opentelemetry.io/docs/specs/otel/trace/api/#behavior-of-the-api-in-the-absence-of-an-installed-sdk
pub const NoopTracer = struct {
    pub const Tracer = trace.Tracer(@This());

    pub fn tracer(self: @This()) @This().Tracer {
        return .{ .impl = self };
    }

    pub const Span = NonRecordingSpan;

    pub fn span(_: @This(), _: std.heap.ArenaAllocator, _: []const u8, _: SpanCreationOptions) !@This().Span {
        return .{ .context = .{
            .trace_id = w3c_trace_context.TraceParent.TraceId.invalid,
            .span_id = w3c_trace_context.TraceParent.ParentId.invalid,
            .trace_flags = .{},
        } };
    }

    pub fn enabled(_: @This()) bool {
        return false;
    }
};

/// https://opentelemetry.io/docs/specs/otel/trace/api/#span
pub fn Span(comptime Impl: type) type {
    return struct {
        // Do not call your own methods in here.
        // Always delegate to `impl` if possible
        // so that we only check `isRecording()` once.

        impl: Impl,

        /// Use this allocator for things you want to outlive the Span.
        pub fn arena(self: utils.meta.LikeReceiver(Impl, .arena, @This())) std.mem.Allocator {
            return self.impl.arena();
        }

        /// Frees everything allocated with `arena()`.
        pub fn deinit(self: utils.meta.LikeReceiver(Impl, .deinit, @This())) void {
            self.impl.deinit();

            switch (@typeInfo(@TypeOf(self))) {
                .Pointer => |pointer| {
                    if (!pointer.is_const)
                        self.* = undefined;
                },
                else => {},
            }
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#get-context
        pub fn getContext(self: @This()) SpanContext {
            return self.impl.getContext();
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#isrecording
        pub fn isRecording(self: @This()) bool {
            return self.impl.isRecording();
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#set-attributes
        /// Do not forget to clone arguments with `arena()` if needed.
        pub fn setAttribute(self: *@This(), key: []const u8, value: api.Attributes.Value) std.mem.Allocator.Error!void {
            if (!self.isRecording()) return;
            try self.impl.setAttribute(key, value);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#set-attributes
        /// Do not forget to clone the attributes with `arena()` if needed.
        pub fn setAttributes(self: *@This(), attributes: api.Attributes) std.mem.Allocator.Error!void {
            if (!self.isRecording()) return;
            if (std.meta.hasMethod(Impl, "setAttributes"))
                try self.impl.setAttributes(attributes)
            else {
                var iter = attributes.map.iterator();
                while (iter.next()) |attribute|
                    try self.impl.setAttribute(attribute.key_ptr.*, attribute.value_ptr.*);
            }
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#add-events
        /// Do not forget to clone the event with `arena()` if needed.
        pub fn addEvent(self: *@This(), event: SpanEvent) std.mem.Allocator.Error!void {
            if (!self.isRecording()) return;
            try self.impl.addEvent(event);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#add-link
        /// Do not forget to clone the link with `arena()` if needed.
        pub fn addLink(self: *@This(), link: SpanLink) std.mem.Allocator.Error!void {
            if (!self.isRecording()) return;
            try self.impl.addLink(link);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#set-status
        pub fn setStatus(self: *@This(), status: SpanStatus) void {
            if (!self.isRecording()) return;
            self.impl.setStatus(status);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#updatename
        /// Do not forget to clone the name with `arena()` if needed.
        pub fn updateName(self: *@This(), name: []const u8) void {
            if (!self.isRecording()) return;
            self.impl.updateName(name);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#end
        pub fn endAt(
            self: *@This(),
            timestamp_ns: i128,
        ) void {
            if (!self.isRecording()) return;
            self.impl.endAt(timestamp_ns);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#end
        pub fn end(self: *@This()) void {
            if (!self.isRecording()) return;
            if (std.meta.hasMethod(Impl, "end"))
                self.impl.end()
            else
                self.impl.endAt(std.time.nanoTimestamp());
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/api/#record-exception
        pub fn recordException(
            self: *@This(),
            err: anyerror,
            escaped: bool,
            error_return_trace: ?*std.builtin.StackTrace,
        ) std.mem.Allocator.Error!void {
            if (!self.isRecording()) return;
            if (std.meta.hasMethod(Impl, "recordException"))
                try self.impl.recordException(err, escaped, error_return_trace)
            else {
                var event = try SpanEvent.fromError(self.arena(), err, escaped, error_return_trace);
                errdefer event.deinit(self.arena());

                try self.impl.addEvent(event);
            }
        }

        pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
            try write_stream.write(self.impl);
        }

        // pub inline fn any(self: *@This()) AnySpan {
        //     return .{
        //         .context = self,
        //         .arenaFn = arena,
        //         .deinitFn = deinit,
        //         .getContextFn = getContext,
        //         .isRecordingFn = isRecording,
        //         .setAttributeFn = setAttribute,
        //         .setAttributesFn = setAttributes,
        //         .addEventFn = addEvent,
        //         .addLinkFn = addLink,
        //         .setStatusFn = setStatus,
        //         .updateNameFn = updateName,
        //         .endAtFn = endAt,
        //         .endFn = end,
        //         .recordExceptionFn = recordException,
        //     };
        // }
    };
}

// pub const AnySpan = struct {
//     context: *anyopaque,
//     arenaFn: *const fn (*anyopaque) std.mem.Allocator,
//     deinitFn: *const fn (*anyopaque) void,
//     getContextFn: *const fn (*const anyopaque) SpanContext,
//     isRecordingFn: *const fn (*const anyopaque) bool,
//     setAttributeFn: *const fn (*anyopaque, []const u8, api.AttributeValue) std.mem.Allocator.Error!void,
//     setAttributesFn: *const fn (*anyopaque, api.Attributes) std.mem.Allocator.Error!void,
//     addEventFn: *const fn (*anyopaque, SpanEvent) std.mem.Allocator.Error!void,
//     addLinkFn: *const fn (*anyopaque, SpanLink) std.mem.Allocator.Error!void,
//     setStatusFn: *const fn (*anyopaque, SpanStatus) void,
//     updateNameFn: *const fn (*anyopaque, []const u8) void,
//     endAtFn: *const fn (*anyopaque, i128) void,
//     endFn: *const fn (*anyopaque) void,
//     recordExceptionFn: *const fn (*anyopaque, anyerror, bool, ?*std.builtin.StackTrace) std.mem.Allocator.Error!void,

//     pub fn arena(self: *@This()) std.mem.Allocator {
//         return self.arenaFn(self.context);
//     }

//     pub fn deinit(self: *@This()) void {
//         self.deinitFn(self);
//         self.* = undefined;
//     }

//     pub fn getContext(self: @This()) SpanContext {
//         return self.getContextFn(self.context);
//     }

//     pub fn isRecording(self: @This()) bool {
//         return self.isRecordingFn(self.context);
//     }

//     pub fn setAttribute(self: *@This(), key: []const u8, value: api.AttributeValue) std.mem.Allocator.Error!void {
//         try self.setAttributeFn(self.context, key, value);
//     }

//     pub fn setAttributes(self: *@This(), attributes: api.Attributes) std.mem.Allocator.Error!void {
//         try self.setAttributesFn(self.context, attributes);
//     }

//     pub fn addEvent(self: *@This(), event: SpanEvent) std.mem.Allocator.Error!void {
//         try self.addEventFn(self.context, event);
//     }

//     pub fn addLink(self: *@This(), link: SpanLink) std.mem.Allocator.Error!void {
//         try self.addLinkFn(self.context, link);
//     }

//     pub fn setStatus(self: *@This(), status: SpanStatus) void {
//         self.setStatusFn(self.context, status);
//     }

//     pub fn updateName(self: *@This(), name: []const u8) void {
//         self.updateNameFn(self.context, name);
//     }

//     pub fn endAt(
//         self: *@This(),
//         timestamp_ns: i128,
//     ) void {
//         self.endAtFn(self.context, timestamp_ns);
//     }

//     pub fn end(self: *@This()) void {
//         self.endFn(self.context);
//     }

//     pub fn recordException(
//         self: *@This(),
//         err: anyerror,
//         escaped: bool,
//         error_return_trace: ?*std.builtin.StackTrace,
//     ) std.mem.Allocator.Error!void {
//         try self.recordExceptionFn(self.context, err, escaped, error_return_trace);
//     }
// };

/// https://opentelemetry.io/docs/specs/otel/trace/api/#spancontext
pub const SpanContext = struct {
    trace_id: w3c_trace_context.TraceParent.TraceId,
    span_id: w3c_trace_context.TraceParent.ParentId,
    trace_flags: w3c_trace_context.TraceParent.TraceFlags = .{},
    trace_state: TraceState = .{},
    is_remote: bool = false,

    /// https://opentelemetry.io/docs/specs/otel/trace/api/#isvalid
    pub fn isValid(self: @This()) bool {
        return self.trace_id.isValid() and self.span_id.isValid();
    }

    pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
        try write_stream.write(.{
            .trace_id = self.trace_id.toHex(),
            .span_id = self.span_id.toHex(),
            .trace_flags = self.trace_flags,
            .trace_state = self.trace_state,
            .is_remote = self.is_remote,
        });
    }
};

/// https://opentelemetry.io/docs/specs/otel/trace/api/#spankind
pub const SpanKind = enum {
    internal,
    client,
    server,
    consumer,
    producer,
};

pub const SpanStatus = union(enum) {
    unset,
    @"error": []const u8,
    ok,

    /// https://opentelemetry.io/docs/specs/otel/trace/api/#set-status
    pub fn update(self: *@This(), new: @This()) void {
        if (@intFromEnum(self.*) < @intFromEnum(new))
            self.* = new;
    }

    test update {
        var status: @This() = .unset;
        status.update(.{ .@"error" = "error" });
        try std.testing.expectEqual(@This().@"error", std.meta.activeTag(status));
        status.update(.unset);
        try std.testing.expectEqual(@This().@"error", std.meta.activeTag(status));
        status.update(.ok);
        try std.testing.expectEqual(@This().ok, status);
        status.update(.unset);
        try std.testing.expectEqual(@This().ok, status);
        status.update(.{ .@"error" = "error" });
        try std.testing.expectEqual(@This().ok, status);
    }
};

pub const SpanEvent = struct {
    name: []const u8,
    timestamp_ns: i128,
    attributes: api.Attributes = .{},

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.attributes.deinit(allocator);
        self.* = undefined;
    }

    // TODO Make this use the semconv definitions once we have them.
    /// https://opentelemetry.io/docs/specs/otel/trace/api/#record-exception
    /// https://opentelemetry.io/docs/specs/otel/trace/exceptions/#attributes
    pub fn fromError(allocator: std.mem.Allocator, err: anyerror, escaped: bool, error_return_trace: ?*std.builtin.StackTrace) std.mem.Allocator.Error!@This() {
        var attributes = api.Attributes{};
        errdefer attributes.deinit(allocator);

        try attributes.map.put(allocator, "exception.type", .{ .one = .{ .string = @errorName(err) } });
        try attributes.map.put(allocator, "exception.escaped", .{ .one = .{ .bool = escaped } });
        if (error_return_trace) |ert| {
            const string = string: {
                var string = std.ArrayListUnmanaged(u8){};
                errdefer string.deinit(allocator);

                try string.writer(allocator).print("{}", .{ert});

                break :string try string.toOwnedSlice(allocator);
            };
            errdefer allocator.free(string);

            try attributes.map.put(allocator, "exception.stacktrace", .{ .one = .{ .string = string } });
        }

        return .{
            .name = "exception",
            .timestamp_ns = std.time.nanoTimestamp(),
            .attributes = attributes,
        };
    }
};

pub const SpanLink = struct {
    context: SpanContext,
    attributes: api.Attributes = .{},
};

/// https://opentelemetry.io/docs/specs/otel/trace/api/#wrapping-a-spancontext-in-a-span
pub fn nonRecordingSpan(context: SpanContext) NonRecordingSpan {
    return .{ .context = context };
}

/// https://opentelemetry.io/docs/specs/otel/trace/api/#wrapping-a-spancontext-in-a-span
const NonRecordingSpan = struct {
    context: SpanContext,
    oom_allocator: std.heap.FixedBufferAllocator = std.heap.FixedBufferAllocator.init(""),

    pub const Span = trace.Span(@This());

    pub inline fn span(self: @This()) @This().Span {
        return .{ .impl = self };
    }

    pub fn arena(self: *@This()) std.mem.Allocator {
        return self.oom_allocator.allocator();
    }

    pub fn deinit(self: *@This()) void {
        self.* = undefined;
    }

    pub fn getContext(self: @This()) SpanContext {
        return self.context;
    }

    pub fn isRecording(_: @This()) bool {
        return false;
    }

    pub fn setAttribute(_: *@This(), _: []const u8, _: api.Attributes.Value) !void {}
    pub fn addEvent(_: *@This(), _: SpanEvent) !void {}
    pub fn addLink(_: *@This(), _: SpanLink) !void {}
    pub fn setStatus(_: *@This(), _: SpanStatus) void {}
    pub fn updateName(_: *@This(), _: []const u8) void {}
    pub fn endAt(_: *@This(), _: i128) void {}
};

// TODO Should this copy keys and values to own them like `std.BufMap`?
/// https://opentelemetry.io/docs/specs/otel/trace/api/#tracestate
pub const TraceState = struct {
    concerns: Concerns = .{},
    /// Entries from other tracing systems.
    entries: w3c_trace_context.TraceState = .{},

    pub const Concerns = struct {
        /// The key name to store this under in a `w3c_trace_context.TraceState`.
        key_name: w3c_trace_context.TraceState.Key.Name = .{ .simple = "ot" },
        entries: std.EnumMap(Concern, []const u8) = .{},

        pub const InvalidError = error{InvalidTraceStateConcerns};

        /// https://opentelemetry.io/docs/specs/otel/trace/tracestate-handling/#key
        pub const Concern = enum {
            // TODO Where are these specified?
            p,
            ts,
            s1,

            comptime {
                for (std.enums.values(@This())) |value| {
                    const name = @tagName(value);
                    std.debug.assert(std.ascii.isLower(name[0]));
                    for (name[1..]) |char|
                        std.debug.assert(std.ascii.isLower(char) or std.ascii.isDigit(char));
                }
            }
        };

        const string_separator = ";";
        const string_assignment = ":";

        /// https://opentelemetry.io/docs/specs/otel/trace/tracestate-handling/#value
        fn validateValue(value: []const u8) InvalidError!void {
            for (value) |char|
                if (switch (char) {
                    '.', '_', '-' => continue,
                    else => |c| !std.ascii.isAlphanumeric(c),
                })
                    return error.InvalidTraceStateConcerns;
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/tracestate-handling/#setting-values
        pub fn put(self: *@This(), concern: Concern, value: []const u8) InvalidError!void {
            try validateValue(value);

            self.entries.put(concern, value);

            if (self.stringLength() > w3c_trace_context.TraceState.max_value_len)
                return error.InvalidTraceStateConcerns;
        }

        pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
            if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
                try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

            var entries = self.entries;
            var iter = entries.iterator();
            var first = true;
            while (iter.next()) |entry| {
                if (first)
                    first = false
                else
                    try writer.writeAll(string_separator);
                try writer.writeAll(@tagName(entry.key));
                try writer.writeAll(string_assignment);
                try writer.writeAll(entry.value.*);
            }
        }

        pub fn stringLength(self: @This()) usize {
            var string_len = self.key_name.stringLength() + w3c_trace_context.TraceState.string_assignment.len;

            {
                var copy = self.entries;

                var iter = copy.iterator();
                while (iter.next()) |entry|
                    string_len += @tagName(entry.key).len + string_assignment.len + entry.value.len;
            }

            string_len += (self.entries.count() -| 1) * string_separator.len;

            return string_len;
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

        test "toString" {
            const allocator = std.testing.allocator;

            var self = @This(){};

            try self.put(.p, "foo");
            try self.put(.ts, "bar");
            try self.put(.s1, "baz");

            var string = std.ArrayListUnmanaged(u8){};
            defer string.deinit(allocator);

            try self.toString(string.writer(allocator));

            try std.testing.expectEqualStrings("p:foo;ts:bar;s1:baz", string.items);
        }
    };

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    /// Configures the given limits so that `concerns` are taken into account.
    /// You can then use them on `entries`.
    pub fn adjustPruneLimits(self: @This(), limits: *w3c_trace_context.TraceState.PruneLimits) w3c_trace_context.TraceState.PruneError!void {
        if (limits.entries == 0)
            return error.TraceStateLimitsTooAggressive;
        limits.entries -= 1;

        if (limits.string_len) |*string_len| {
            const concerns_string_len = self.concerns.stringLength();
            if (string_len.* < concerns_string_len)
                return error.TraceStateLimitsTooAggressive;
            string_len.* -|= concerns_string_len + w3c_trace_context.TraceState.string_separator.len;
        }
    }

    test adjustPruneLimits {
        const allocator = std.testing.allocator;

        var self = @This(){};
        defer self.deinit(allocator);

        try self.concerns.put(.p, "p");
        try self.entries.put(allocator, .{ .simple = "a" }, "a");
        try self.entries.put(allocator, .{ .simple = "b" }, "b");

        try std.testing.expectEqual(0, try self.entries.prune(limits: {
            var limits = w3c_trace_context.TraceState.PruneLimits{
                .string_len = self.stringLength(),
            };
            try self.adjustPruneLimits(&limits);
            break :limits limits;
        }));

        try std.testing.expectEqual(1, try self.entries.prune(limits: {
            var limits = w3c_trace_context.TraceState.PruneLimits{
                .string_len = self.stringLength() - 1,
            };
            try self.adjustPruneLimits(&limits);
            break :limits limits;
        }));
    }

    pub fn toString(self: @This(), writer: anytype) @TypeOf(writer).Error!void {
        if (comptime @TypeOf(writer) == std.ArrayListUnmanaged(u8).Writer)
            try writer.context.self.ensureUnusedCapacity(writer.context.allocator, self.stringLength());

        // A W3C TraceContext vendor must put itself in the front.
        if (self.concerns.entries.count() != 0) {
            try self.concerns.key_name.toString(writer);
            try writer.writeAll(w3c_trace_context.TraceState.string_assignment);
            try self.concerns.toString(writer);

            if (self.entries.entries.count() != 0)
                try writer.writeAll(w3c_trace_context.TraceState.string_separator);
        }

        try self.entries.toString(writer);
    }

    pub fn stringLength(self: @This()) usize {
        return self.concerns.stringLength() + if (self.entries.entries.count() != 0)
            w3c_trace_context.TraceState.string_separator.len +
                self.entries.stringLength()
        else
            0;
    }

    test toString {
        const allocator = std.testing.allocator;

        var self = @This(){};
        defer self.deinit(allocator);

        try self.concerns.put(.p, "p");
        try self.entries.put(allocator, .{ .simple = "b" }, "b");
        try self.entries.put(allocator, .{ .simple = "a" }, "a");

        self.entries.sort();

        try std.testing.expectFmt("ot=p:p,a=a,b=b", "{}", .{self});
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
};

test {
    std.testing.refAllDeclsRecursive(@This());
}

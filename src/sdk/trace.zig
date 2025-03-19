const builtin = @import("builtin");
const std = @import("std");
const protobuf = @import("protobuf");
const utils = @import("utils");

const w3c_trace_context = @import("w3c-trace-context");
const otlp = @import("otlp");

const sdk = @import("../sdk.zig");

const api = api: {
    const toplevel = @import("api");

    break :api struct {
        usingnamespace toplevel.trace;

        const Attributes = toplevel.Attributes;
        const InstrumentationScope = toplevel.InstrumentationScope;
    };
};

const Resource = @import("Resource.zig");

const trace = @This();

const log = utils.log.scoped(.otel);

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#tracer-provider
/// Must stay in the same position in memory at all times
/// so that pointers to it are not broken.
pub fn TracerProvider(
    comptime IdGeneratorType: type,
    comptime SpanProcessorType: type,
    comptime tracerConfigurator: TracerConfigurator,
) type {
    return struct {
        resource: Resource,
        id_generator: IdGeneratorType,
        span_processor: SpanProcessorType,

        span_refcount_pool: std.heap.MemoryPool(std.atomic.Value(usize)),
        span_refcount_pool_mutex: std.Thread.Mutex = .{},

        // Not named `tracerProvider()` because `@This()` already is a valid implementation of the interface
        // and we do not need to wrap it in a `trace.api.TracerProvider` to make it behave correctly.
        // In fact, the type resulting from wrapping it removes public methods, thereby offering only a subset.
        pub inline fn api(self: anytype, comptime iface: utils.meta.IfaceCtx) trace.api.TracerProvider(iface.Type(@This())) {
            return .{ .impl = iface.context(self) };
        }

        pub const Tracer = trace.Tracer(@This());

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#tracer-creation
        pub fn tracer(
            self: *@This(),
            /// Scopes are compared by their pointer
            /// so do not pass in pointers to multiple identical instances!
            /// This is relied upon by the `SpanProcessor` to separate batches.
            /// However, the worst that can happen is inefficency
            /// in runtime performance and data emitted by the exporter
            /// due to unnecessarily many calls to `SpanExporter.export()`
            /// with separate batches that could have been one.
            instrumentation_scope: *const trace.api.InstrumentationScope,
        ) @This().Tracer {
            return .{
                .provider = self,
                .config = tracerConfigurator(instrumentation_scope),
                .instrumentation_scope = instrumentation_scope,
            };
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#shutdown
        pub fn shutdown(self: *@This(), timeout_ms: ?u32) error{Timeout}!void {
            defer self.span_refcount_pool.deinit();
            try self.span_processor.shutdown(timeout_ms);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#forceflush
        pub fn forceFlush(
            self: utils.meta.LikeReceiver(SpanProcessorType, .forceFlush, @This()),
            timeout_ms: ?u32,
        ) error{Timeout}!void {
            try self.span_processor.forceFlush(timeout_ms);
        }
    };
}

pub fn tracerProvider(
    resource: Resource,
    id_generator: anytype,
    span_processor: anytype,
    tracerConfigurator: TracerConfigurator,
    span_refcount_pool: std.heap.MemoryPool(std.atomic.Value(usize)),
) TracerProvider(
    @TypeOf(id_generator),
    @TypeOf(span_processor),
    tracerConfigurator,
) {
    return .{
        .resource = resource,
        .id_generator = id_generator,
        .span_processor = span_processor,
        .span_refcount_pool = span_refcount_pool,
    };
}

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#tracerconfigurator
pub const TracerConfigurator = fn (*const api.InstrumentationScope) *const TracerConfig;

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#tracerconfig
pub const TracerConfig = struct {
    disabled: bool = false,
};

pub fn defaultTracerConfigurator(_: *const api.InstrumentationScope) *const TracerConfig {
    return &.{};
}

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#tracer
pub fn Tracer(comptime TracerProviderType: type) type {
    return struct {
        comptime {
            _ = std.testing.refAllDecls(trace.api.Tracer(@This()));
        }

        provider: *TracerProviderType,
        config: *const TracerConfig,
        instrumentation_scope: *const trace.api.InstrumentationScope,

        // Not named `tracer()` because `@This()` already is a valid implementation of the interface
        // and we do not need to wrap it in a `trace.api.Tracer` to make it behave correctly.
        // In fact, the type resulting from wrapping it removes public methods, thereby offering only a subset.
        pub inline fn api(self: anytype, comptime iface: utils.meta.IfaceCtx) trace.api.Tracer(iface.Type(@This())) {
            return .{ .impl = iface.context(self) };
        }

        pub const Span = trace.Span;

        pub fn span(
            self: *const @This(),
            /// Backing allocator must stay alive until
            /// the span processor is done and calls `Span.deinit()`.
            arena: std.heap.ArenaAllocator,
            /// Must outlive this span just like `arena`'s backing allocator.
            name: []const u8,
            /// Any allocations backing this must reside in `arena`.
            options: trace.api.SpanCreationOptions,
        ) !@This().Span {
            const refcount = refcount: {
                self.provider.span_refcount_pool_mutex.lock();
                defer self.provider.span_refcount_pool_mutex.unlock();

                break :refcount try self.provider.span_refcount_pool.create();
            };
            errdefer self.provider.span_refcount_pool.free(refcount);

            refcount.* = .{ .raw = 0 };

            var s = (RecordingSpan{
                .refcount = refcount,
                .refcount_pool = &self.provider.span_refcount_pool,
                .refcount_pool_mutex = &self.provider.span_refcount_pool_mutex,

                .processor = self.provider.span_processor.any(),

                .resource = &self.provider.resource,
                .instrumentation_scope = self.instrumentation_scope,

                .arena_ = arena,

                .name = name,
                .context = .{
                    .trace_id = if (options.parent) |parent|
                        parent.trace_id
                    else
                        self.provider.id_generator.generateTraceId(),
                    .span_id = self.provider.id_generator.generateSpanId(),
                },
                .parent = options.parent,
                .kind = options.kind,
                .start_ns = options.start_ns orelse std.time.nanoTimestamp(),
                .attributes = options.attributes,
                .links = options.links,
            }).span();
            errdefer s.deinit();

            self.provider.span_processor.onStart(&s, {});

            return s;
        }

        pub fn enabled(self: @This()) bool {
            return !self.config.disabled;
        }
    };
}

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#additional-span-interfaces
///
/// - readable span: `*const Span` or a `Span` copy
/// - read/write span: `*Span`
///
/// Changes to one copy may invalidate other copies.
/// Calling `deinit()` on any copy may invalidate all copies.
/// Therefore it is advised to copy only when moving ownership.
pub const Span = api.Span(RecordingSpan);

/// It is not advisable to use this as it is.
/// Instead, obtain a well-behaved interface using `span()`.
/// Its notes about copying apply to this as well.
const RecordingSpan = struct {
    refcount: *std.atomic.Value(usize),
    refcount_pool: *std.heap.MemoryPool(std.atomic.Value(usize)),
    refcount_pool_mutex: *std.Thread.Mutex,

    // XXX Get rid of virtual calls here
    // by switching on a global comptime-known union type
    // configurable in `@import("root").otel_options`.
    processor: AnySpanProcessor,

    resource: *const sdk.Resource,
    instrumentation_scope: *const api.InstrumentationScope,

    arena_: std.heap.ArenaAllocator,

    name: []const u8,
    context: api.SpanContext,
    parent: ?api.SpanContext = null,
    kind: api.SpanKind = .internal,
    start_ns: i128,
    end_ns: ?i128 = null,
    attributes: api.Attributes = .{},
    links: std.ArrayListUnmanaged(api.SpanLink) = .{},
    events: std.ArrayListUnmanaged(api.SpanEvent) = .{},
    /// Do not set manually, use `setStatus()` instead.
    status: api.SpanStatus = .unset,

    pub inline fn span(self: @This()) api.Span(@This()) {
        return .{ .impl = self };
    }

    pub fn arena(self: *@This()) std.mem.Allocator {
        return self.arena_.allocator();
    }

    pub fn ref(self: *@This()) void {
        _ = self.refcount.fetchAdd(1, .monotonic);
    }

    pub fn deinit(self: @This()) void {
        // See `RefCount` in `std.atomic.Value`'s `test Value`
        // for an explanation on the atomic order.
        if (self.refcount.fetchSub(1, .release) == 1) {
            _ = self.refcount.load(.acquire);

            {
                self.refcount_pool_mutex.lock();
                defer self.refcount_pool_mutex.unlock();

                self.refcount_pool.destroy(self.refcount);
            }

            self.arena_.deinit();
        }
    }

    pub fn getContext(self: @This()) api.SpanContext {
        return self.context;
    }

    pub fn setAttribute(self: *@This(), key: []const u8, value: api.Attributes.Value) !void {
        try self.attributes.map.put(self.arena(), key, value);
    }

    pub fn isRecording(self: @This()) bool {
        return self.end_ns == null;
    }

    pub fn addEvent(self: *@This(), event: api.SpanEvent) !void {
        try self.events.append(self.arena(), event);
    }

    pub fn addLink(self: *@This(), link: api.SpanLink) !void {
        try self.links.append(self.arena(), link);
    }

    pub fn setStatus(self: *@This(), status: api.SpanStatus) void {
        self.status.update(status);
    }

    pub fn updateName(self: *@This(), name: []const u8) void {
        self.name = name;
    }

    pub fn endAt(
        self: *@This(),
        timestamp_ns: i128,
    ) void {
        {
            var iface = self.span();
            self.processor.onEnding(&iface);
            self.* = iface.impl;
        }

        self.end_ns = timestamp_ns;

        self.processor.onEnd(self.span());
    }

    pub fn jsonStringify(self: @This(), write_stream: anytype) !void {
        try write_stream.write(.{
            .scope = self.instrumentation_scope,
            .name = self.name,
            .context = self.context,
            .parent = self.parent,
            .kind = self.kind,
            .start_ns = self.start_ns,
            .end_ns = self.end_ns,
            .attributes = self.attributes,
            .links = self.links.items,
            .events = self.events.items,
            .status = self.status,
        });
    }
};

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#id-generators
pub fn IdGenerator(comptime Impl: type) type {
    return struct {
        impl: Impl,

        pub fn generateTraceId(self: utils.meta.LikeReceiver(Impl, .generateTraceId, @This())) w3c_trace_context.TraceParent.TraceId {
            return self.impl.generateTraceId();
        }

        pub fn generateSpanId(self: utils.meta.LikeReceiver(Impl, .generateSpanId, @This())) w3c_trace_context.TraceParent.ParentId {
            return self.impl.generateSpanId();
        }

        // pub inline fn any(self: *@This()) AnyIdGenerator {
        //     return .{
        //         .context = &self.impl,
        //         .generateTraceIdFn = typeErasedGenerateTraceIdBytesFn,
        //         .generateSpanIdFn = typeErasedGenerateSpanIdBytesFn,
        //     };
        // }

        // fn typeErasedGenerateTraceIdBytesFn(context: *anyopaque) api.SpanContext.TraceId {
        //     const ptr: *Impl = @alignCast(@ptrCast(context));
        //     return ptr.*.generateTraceId();
        // }

        // fn typeErasedGenerateSpanIdBytesFn(context: *anyopaque) api.SpanContext.SpanId {
        //     const ptr: *Impl = @alignCast(@ptrCast(context));
        //     return ptr.*.generateSpanId();
        // }
    };
}

// pub const AnyIdGenerator = struct {
//     context: *anyopaque,
//     generateTraceIdFn: *const fn (*anyopaque) api.SpanContext.TraceId,
//     generateSpanIdFn: *const fn (*anyopaque) api.SpanContext.SpanId,

//     pub fn generateTraceId(self: *@This()) api.SpanContext.TraceId {
//         return self.generateTraceIdFn(self.context);
//     }

//     pub fn generateSpanId(self: *@This()) api.SpanContext.SpanId {
//         return self.generateSpanIdFn(self.context);
//     }
// };

pub const SequentialIdGenerator = struct {
    next_trace_id: IdInt(w3c_trace_context.TraceParent.TraceId) = 1,
    next_span_id: IdInt(w3c_trace_context.TraceParent.ParentId) = 1,
    endian: std.builtin.Endian = .big,

    fn IdInt(Id: type) type {
        const info = @typeInfo(std.meta.FieldType(Id, .bytes));
        return std.meta.Int(.unsigned, info.array.len * @typeInfo(info.array.child).int.bits);
    }

    pub inline fn idGenerator(self: anytype, comptime iface: utils.meta.IfaceCtx) IdGenerator(iface.Type(@This())) {
        return .{ .impl = iface.context(self) };
    }

    pub fn generateTraceId(self: *@This()) w3c_trace_context.TraceParent.TraceId {
        defer self.next_trace_id += 1;
        return .{ .bytes = std.mem.toBytes(std.mem.nativeTo(
            IdInt(w3c_trace_context.TraceParent.TraceId),
            self.next_trace_id,
            self.endian,
        )) };
    }

    pub fn generateSpanId(self: *@This()) w3c_trace_context.TraceParent.ParentId {
        defer self.next_span_id += 1;
        return .{ .bytes = std.mem.toBytes(std.mem.nativeTo(
            IdInt(w3c_trace_context.TraceParent.ParentId),
            self.next_span_id,
            self.endian,
        )) };
    }
};

pub fn sequentialIdGenerator(init: SequentialIdGenerator) IdGenerator(SequentialIdGenerator) {
    return init.idGenerator(.copy);
}

test sequentialIdGenerator {
    var id_gen = sequentialIdGenerator(.{
        .endian = builtin.cpu.arch.endian(),
    });
    // var any_id_gen = id_gen.any();

    // try std.testing.expectEqual(std.mem.toBytes(@as(SequentialIdGenerator.IdInt(w3c_trace_context.TraceParent.TraceId), 1)), any_id_gen.generateTraceId().bytes);
    try std.testing.expectEqual(std.mem.toBytes(@as(SequentialIdGenerator.IdInt(w3c_trace_context.TraceParent.TraceId), 1)), id_gen.generateTraceId().bytes);

    // try std.testing.expectEqual(std.mem.toBytes(@as(SequentialIdGenerator.IdInt(w3c_trace_context.TraceParent.ParentId), 1)), any_id_gen.generateSpanId().bytes);
    try std.testing.expectEqual(std.mem.toBytes(@as(SequentialIdGenerator.IdInt(w3c_trace_context.TraceParent.ParentId), 1)), id_gen.generateSpanId().bytes);
}

pub const RandomIdGenerator = struct {
    random: std.Random,

    pub inline fn idGenerator(self: anytype, comptime iface: utils.meta.IfaceCtx) IdGenerator(iface.Type(@This())) {
        return .{ .impl = iface.context(self) };
    }

    pub fn generateTraceId(self: @This()) w3c_trace_context.TraceParent.TraceId {
        var id: w3c_trace_context.TraceParent.TraceId = undefined;
        self.random.bytes(&id.bytes);
        return id;
    }

    pub fn generateSpanId(self: @This()) w3c_trace_context.TraceParent.ParentId {
        var id: w3c_trace_context.TraceParent.ParentId = undefined;
        self.random.bytes(&id.bytes);
        return id;
    }
};

pub fn randomIdGenerator(random: std.Random) IdGenerator(RandomIdGenerator) {
    return (RandomIdGenerator{ .random = random }).idGenerator(.copy);
}

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#span-processor
pub fn SpanProcessor(
    comptime Impl: type,
    comptime SpanExporterType: type,
) type {
    _ = std.testing.refAllDecls(SpanExporter(utils.meta.ChildOrelseSelf(SpanExporterType)));
    std.debug.assert(std.meta.FieldType(utils.meta.ChildOrelseSelf(Impl), .exporter) == SpanExporterType);

    return struct {
        //! https://opentelemetry.io/docs/specs/otel/trace/sdk/#interface-definition

        impl: Impl,

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#onstart
        pub fn onStart(
            self: utils.meta.LikeReceiver(Impl, .onStart, @This()),
            span: *Span,
            parent_context: void,
        ) void {
            self.impl.onStart(span, parent_context);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#onending
        pub fn onEnding(
            self: utils.meta.LikeReceiver(Impl, .onEnding, @This()),
            span: *Span,
        ) void {
            std.debug.assert(span.isRecording());
            span.impl.ref();
            self.impl.onEnding(span);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#onendspan
        pub fn onEnd(
            self: utils.meta.LikeReceiver(Impl, .onEnd, @This()),
            span: Span,
        ) void {
            std.debug.assert(!span.isRecording());
            self.impl.onEnd(span);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#shutdown-1
        pub fn shutdown(self: *@This(), timeout_ms: ?u32) error{Timeout}!void {
            var timer = if (timeout_ms) |_|
                std.time.Timer.start() catch |err| std.debug.panic("{s}", .{@errorName(err)})
            else
                null;

            var timed_out = false;

            self.forceFlush(
                if (timeout_ms) |t_ms| t_ms / 3 else null,
            ) catch |err| switch (err) {
                error.Timeout => timed_out = true,
            };
            self.impl.exporter.shutdown(
                if (timeout_ms) |t_ms| t_ms / 3 + t_ms / 3 - @as(u32, @intCast(timer.?.read() / std.time.ns_per_ms)) else null,
            ) catch |err| switch (err) {
                error.Timeout => timed_out = true,
            };
            self.impl.shutdown(
                if (timeout_ms) |t_ms| t_ms - @as(u32, @intCast(timer.?.read() / std.time.ns_per_ms)) else null,
            ) catch |err| switch (err) {
                error.Timeout => timed_out = true,
            };

            self.* = undefined;

            if (timed_out) return error.Timeout;
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#forceflush-1
        pub fn forceFlush(
            self: utils.meta.LikeReceiver(Impl, .forceFlush, @This()),
            timeout_ms: ?u32,
        ) error{Timeout}!void {
            var timer = if (timeout_ms) |_|
                std.time.Timer.start() catch |err| std.debug.panic("{s}", .{@errorName(err)})
            else
                null;

            var timed_out = false;

            self.impl.forceFlush(
                if (timeout_ms) |t_ms| t_ms / 2 else null,
            ) catch |err| switch (err) {
                error.Timeout => timed_out = true,
            };

            self.impl.exporter.forceFlush(
                if (timeout_ms) |t_ms| t_ms - @as(u32, @intCast(timer.?.read() / std.time.ns_per_ms)) else null,
            ) catch |err| switch (err) {
                error.Timeout => timed_out = true,
            };

            if (timed_out) return error.Timeout;
        }

        pub inline fn any(self: *@This()) AnySpanProcessor {
            return .{
                .context = self,
                .onStartFn = typeErasedOnStartFn,
                .onEndingFn = typeErasedOnEndingFn,
                .onEndFn = typeErasedOnEndFn,
                .shutdownFn = typeErasedShutdownFn,
                .forceFlushFn = typeErasedForceFlushFn,
            };
        }

        fn typeErasedOnStartFn(context: *anyopaque, span: *Span, parent_context: void) void {
            const self: *@This() = @alignCast(@ptrCast(context));
            self.onStart(span, parent_context);
        }

        fn typeErasedOnEndingFn(context: *anyopaque, span: *Span) void {
            const self: *@This() = @alignCast(@ptrCast(context));
            self.onEnding(span);
        }

        fn typeErasedOnEndFn(context: *anyopaque, span: Span) void {
            const self: *@This() = @alignCast(@ptrCast(context));
            self.onEnd(span);
        }

        fn typeErasedShutdownFn(context: *anyopaque, timeout_ms: ?u32) !void {
            const self: *@This() = @alignCast(@ptrCast(context));
            try self.shutdown(timeout_ms);
        }

        fn typeErasedForceFlushFn(context: *anyopaque, timeout_ms: ?u32) !void {
            const self: *@This() = @alignCast(@ptrCast(context));
            try self.forceFlush(timeout_ms);
        }
    };
}

pub const AnySpanProcessor = struct {
    context: *anyopaque,
    onStartFn: *const fn (*anyopaque, *Span, void) void,
    onEndingFn: *const fn (*anyopaque, *Span) void,
    onEndFn: *const fn (*anyopaque, Span) void,
    shutdownFn: *const fn (*anyopaque, ?u32) error{Timeout}!void,
    forceFlushFn: *const fn (*anyopaque, ?u32) error{Timeout}!void,

    pub fn onStart(self: @This(), span: *Span, parent_context: void) void {
        self.onStartFn(self.context, span, parent_context);
    }

    pub fn onEnding(self: @This(), span: *Span) void {
        self.onEndingFn(self.context, span);
    }

    pub fn onEnd(self: @This(), span: Span) void {
        self.onEndFn(self.context, span);
    }

    pub fn shutdown(self: @This(), timeout_ms: ?u32) error{Timeout}!void {
        try self.shutdownFn(self.context, timeout_ms);
    }

    pub fn forceFlush(self: @This(), timeout_ms: ?u32) error{Timeout}!void {
        try self.forceFlushFn(self.context, timeout_ms);
    }
};

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#simple-processor
pub fn SimpleSpanProcessor(comptime SpanExporterType: type) type {
    return struct {
        //! It is not advisable to use this as it is.
        //! Instead, obtain a well-behaved interface using `spanProcessor()`.

        exporter: SpanExporterType,
        export_mutex: std.Thread.Mutex = .{},

        pub inline fn spanProcessor(self: anytype, comptime iface: utils.meta.IfaceCtx) SpanProcessor(
            iface.Type(@This()),
            SpanExporterType,
        ) {
            return .{ .impl = iface.context(self) };
        }

        pub fn onStart(_: @This(), _: *Span, _: void) void {}

        pub fn onEnding(_: @This(), _: *Span) void {}

        pub fn onEnd(self: *@This(), span: Span) void {
            self.export_mutex.lock();
            defer self.export_mutex.unlock();

            self.exporter.@"export"(&.{span}, null, *const void, &{}, exportCallback);
        }

        fn exportCallback(_: *const void, batch: []const Span, err: SpanExporterType.Error!void) void {
            if (err) |_| {} else |e| log.err("{s}: failed to export batch", .{@errorName(e)});

            for (batch) |span|
                span.deinit();
        }

        pub fn shutdown(self: *@This(), _: ?u32) !void {
            self.* = undefined;
        }

        pub fn forceFlush(_: *@This(), _: ?u32) !void {}
    };
}

pub fn simpleSpanProcessor(exporter: anytype) SimpleSpanProcessor(@TypeOf(exporter)) {
    return .{ .exporter = exporter };
}

pub const BatchingSpanProcessorConfig = struct {
    max_queue_size: comptime_int = 2048,
};

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#batching-processor
pub fn BatchingSpanProcessor(
    comptime SpanExporterType: type,
    comptime config: BatchingSpanProcessorConfig,
) type {
    return struct {
        //! It is not advisable to use this as it is.
        //! Instead, obtain a well-behaved interface using `spanProcessor()`.

        exporter: SpanExporterType,

        max_export_batch_size: std.math.IntFittingRange(0, config.max_queue_size) = @min(config.max_queue_size, 512),
        scheduled_delay_ms: u32 = 5000,
        export_timeout_ms: u32 = 30000,

        queue: Queue = Queue.init(),
        /// Must be held to mutate the `queue`
        /// or anything else during a running export.
        mutex: std.Thread.Mutex = .{},
        process_thread: std.Thread = undefined,
        export_start_event: std.Thread.ResetEvent = .{},
        export_done_event: std.Thread.ResetEvent = .{},
        shutting_down: bool = false,
        force_flush_timeout_ms: ?u32 = null,

        const Queue = std.fifo.LinearFifo(Span, .{ .Static = config.max_queue_size });

        pub fn init(self: *@This()) !void {
            self.process_thread = try std.Thread.spawn(.{}, process, .{self});
        }

        fn process(self: *@This()) void {
            while (true) : (self.export_start_event.reset()) {
                self.export_start_event.timedWait(@as(u64, self.scheduled_delay_ms) * std.time.ns_per_ms) catch |err| switch (err) {
                    error.Timeout => {},
                };
                if (self.shutting_down) break;

                self.mutex.lock();
                defer self.mutex.unlock();

                var timer = if (self.force_flush_timeout_ms != null)
                    std.time.Timer.start() catch |err| std.debug.panic("{s}", .{@errorName(err)})
                else
                    null;

                while (self.queue.readableLength() != 0) : (if (self.force_flush_timeout_ms == null) break) {
                    const batch = self.queue.readableSliceOfLen(@min(self.max_export_batch_size, self.queue.readableLength()));

                    const export_timeout_ms = if (self.force_flush_timeout_ms) |fft_ms| export_timeout_ms: {
                        const time_left_ms = fft_ms -| timer.?.read() / std.time.ns_per_ms;
                        if (time_left_ms == 0) break;
                        break :export_timeout_ms @min(self.export_timeout_ms, time_left_ms);
                    } else self.export_timeout_ms;

                    self.exporter.@"export"(batch, export_timeout_ms, *const void, &{}, exportCallback);

                    self.queue.discard(batch.len);
                }

                self.export_done_event.set();
            }
        }

        pub inline fn spanProcessor(self: anytype, comptime iface: utils.meta.IfaceCtx) trace.SpanProcessor(
            iface.Type(@This()),
            SpanExporterType,
        ) {
            return .{ .impl = iface.context(self) };
        }

        pub fn onStart(_: @This(), _: *Span, _: void) void {}

        pub fn onEnding(_: @This(), _: *Span) void {}

        pub fn onEnd(self: *@This(), span: Span) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.queue.writeItem(span) catch |err| switch (err) {
                error.OutOfMemory => |e| {
                    log.warn(
                        "{s}: dropping span {}, max queue size is {d}",
                        .{ @errorName(e), span.getContext().span_id, self.queue.buf.len },
                    );
                    return;
                },
            };

            if (self.queue.readableLength() == self.max_export_batch_size)
                self.export_start_event.set();
        }

        fn exportCallback(_: *const void, batch: []const Span, err: (SpanExporterType.Error || error{Timeout})!void) void {
            if (err) |_| {} else |e| log.err("{s}: failed to export batch of size {d}", .{ @errorName(e), batch.len });

            for (batch) |span|
                span.deinit();
        }

        pub fn shutdown(self: *@This(), _: ?u32) !void {
            self.shutting_down = true;
            self.export_start_event.set();
            self.process_thread.join();

            {
                self.mutex.lock();
                defer self.mutex.unlock();

                if (self.queue.readableLength() != 0)
                    exportCallback(&{}, self.queue.readableSliceOfLen(self.queue.readableLength()), error.Timeout);

                self.queue.deinit();
            }

            self.* = undefined;
        }

        pub fn forceFlush(self: *@This(), timeout_ms: ?u32) error{Timeout}!void {
            {
                self.mutex.lock();
                defer self.mutex.unlock();

                self.force_flush_timeout_ms = timeout_ms;
            }

            defer {
                self.mutex.lock();
                defer self.mutex.unlock();

                self.force_flush_timeout_ms = null;
            }

            self.export_done_event.reset();
            defer self.export_done_event.reset();

            self.export_start_event.set();

            if (timeout_ms) |t_ms|
                try self.export_done_event.timedWait(t_ms)
            else
                self.export_done_event.wait();
        }
    };
}

pub fn batchingSpanProcessor(
    exporter: anytype,
    config: BatchingSpanProcessorConfig,
) BatchingSpanProcessor(
    @TypeOf(exporter),
    config,
) {
    return .{ .exporter = exporter };
}

pub fn MultiSpanProcessor(
    /// A struct or tuple of fields that are all span processors.
    Processors: type,
) type {
    return struct {
        //! It is not advisable to use this as it is.
        //! Instead, obtain a well-behaved interface using `spanProcessor()`.

        processors: Processors,
        exporter: NullSpanExporter = .{},

        pub inline fn spanProcessor(self: anytype, comptime iface: utils.meta.IfaceCtx) SpanProcessor(iface.Type(@This()), NullSpanExporter) {
            return .{ .impl = iface.context(self) };
        }

        pub fn onStart(self: @This(), span: *Span, parent_context: void) void {
            inline for (@typeInfo(Processors).@"struct".fields) |field| {
                @field(self.processors, field.name).onStart(span, parent_context);
            }
        }

        pub fn onEnding(self: @This(), span: *Span) void {
            inline for (@typeInfo(Processors).@"struct".fields) |field|
                @field(self.processors, field.name).onEnding(span);
        }

        pub fn onEnd(self: *@This(), span: Span) void {
            const fields = @typeInfo(Processors).@"struct".fields;

            // Every processor incremented the reference count in `onEnding()`, including ourselves.
            std.debug.assert(span.impl.refcount.load(.monotonic) == fields.len + 1);

            // Decremented the reference count by one
            // to account for our own reference.
            span.deinit();

            inline for (fields) |field|
                @field(self.processors, field.name).onEnd(span);
        }

        pub fn shutdown(self: *@This(), timeout_ms: ?u32) !void {
            return self.shutdownOrForceFlush(.shutdown, timeout_ms);
        }

        pub fn forceFlush(self: *@This(), timeout_ms: ?u32) !void {
            return self.shutdownOrForceFlush(.force_flush, timeout_ms);
        }

        fn shutdownOrForceFlush(self: *@This(), comptime which: enum { shutdown, force_flush }, timeout_ms: ?u32) error{Timeout}!void {
            var timed_out = false;

            const fields = @typeInfo(Processors).@"struct".fields;

            const each_timeout_ms = if (timeout_ms) |t_ms|
                (if (std.math.cast(u32, fields.len)) |num_processors|
                    t_ms / num_processors
                else
                    0)
            else
                null;

            inline for (fields) |field| {
                const processor = &@field(self.processors, field.name);
                (switch (which) {
                    .shutdown => processor.*.shutdown(each_timeout_ms),
                    .force_flush => processor.*.forceFlush(each_timeout_ms),
                }) catch |err| switch (err) {
                    error.Timeout => timed_out = true,
                };
            }

            if (timed_out) return error.Timeout;
        }
    };
}

pub fn multiSpanProcessor(processors: anytype) SpanProcessor(
    MultiSpanProcessor(@TypeOf(processors)),
    NullSpanExporter,
) {
    return (MultiSpanProcessor(@TypeOf(processors)){ .processors = processors }).spanProcessor(.copy);
}

test MultiSpanProcessor {
    var resource = try Resource.default(std.testing.allocator, @src().fn_name);
    defer resource.attributes.deinit(std.testing.allocator);

    var provider = tracerProvider(
        resource,
        sequentialIdGenerator(.{
            .next_trace_id = 0xDEAD,
            .next_span_id = 0xBEEF,
        }),
        multiSpanProcessor(processors: {
            // XXX Zig 0.13 compiler crashes if we don't declare the struct here
            // before initializing it so we cannot just do `.{ a, b }`.
            const a = simpleSpanProcessor(null_span_exporter).spanProcessor(.copy);
            const b = simpleSpanProcessor(null_span_exporter).spanProcessor(.copy);
            break :processors std.meta.Tuple(&.{ @TypeOf(a), @TypeOf(b) }){ a, b };
        }),
        defaultTracerConfigurator,
        try std.heap.MemoryPool(std.atomic.Value(usize)).initPreheated(std.testing.allocator, 1),
    );
    var provider_api = provider.api(.ptr);

    var tracer = provider_api.tracer(&.{ .name = @src().fn_name });
    var tracer_api = tracer.api(.ptr);

    var span = try testSpan(&tracer_api);
    span.setStatus(.ok);
    span.endAt(3);

    try provider.shutdown(0);
}

/// https://opentelemetry.io/docs/specs/otel/trace/sdk/#span-exporter
pub fn SpanExporter(comptime Impl: type) type {
    return struct {
        //! https://opentelemetry.io/docs/specs/otel/trace/sdk/#interface-definition-1

        impl: Impl,

        safety_lock: std.debug.SafetyLock = .{},

        pub const Error = utils.meta.ChildOrelseSelf(Impl).Error;

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#exportbatch
        pub fn @"export"(
            self: *@This(),
            // Not `[]const *const Span` so that the `SpanProcessor`
            // does not have to keep spans alive until the callback is called.
            batch: []const Span,
            timeout_ms: ?u32,
            comptime CallbackContext: type,
            callback_context: CallbackContext,
            callback: SpanExportCallback(CallbackContext, Error),
        ) void {
            std.debug.assert(batch.len != 0);

            self.safety_lock.lock();
            defer self.safety_lock.unlock();

            self.impl.@"export"(batch, timeout_ms, CallbackContext, callback_context, callback);
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#shutdown-2
        pub fn shutdown(self: *@This(), timeout_ms: ?u32) error{Timeout}!void {
            {
                self.safety_lock.lock();
                defer self.safety_lock.unlock();

                try self.impl.shutdown(timeout_ms);
            }
            self.* = undefined;
        }

        /// https://opentelemetry.io/docs/specs/otel/trace/sdk/#forceflush-2
        pub fn forceFlush(
            self: utils.meta.LikeReceiver(Impl, .forceFlush, @This()),
            timeout_ms: ?u32,
        ) error{Timeout}!void {
            try self.impl.forceFlush(timeout_ms);
        }

        // pub inline fn any(self: *@This()) AnySpanExporter {
        //     return .{
        //         .context = self,
        //         .exportFn = typeErasedExportFn,
        //         .shutdownFn = shutdown,
        //         .forceFlushFn = forceFlush,
        //     };
        // }

        // fn typeErasedExportFn(
        //     context: *anyopaque,
        //     batch: []const api.AnySpan,
        //     timeout_ms: ?u32,
        //     callback_context: *const anyopaque,
        //     callback: SpanExportCallback(*const anyopaque, AnySpanExporter.Error),
        // ) void {
        //     const self: *@This() = @alignCast(@ptrCast(context));
        //     self.@"export"(batch, timeout_ms, *const anyopaque, callback_context, callback);
        // }
    };
}

pub fn SpanExportCallback(comptime Context: type, comptime Error: type) type {
    return fn (
        Context,
        []const Span,
        // XXX `?Error` would make more sense
        // but with that we run into some edge cases
        // that cause errors like this with the LLVM backend:
        // > Invalid record (Producer: 'zig 0.13.0' Reader: 'LLVM 18.1.8')
        Error!void,
    ) void;
}

/// Does not do anything except calling the callback.
/// Probably only useful for testing.
pub const NullSpanExporter = struct {
    pub const Error = error{};

    pub inline fn spanExporter(self: anytype, comptime iface: utils.meta.IfaceCtx) SpanExporter(iface.Type(@This())) {
        return .{ .impl = iface.context(self) };
    }

    pub fn @"export"(
        _: *@This(),
        batch: []const Span,
        _: ?u32,
        comptime CallbackContext: type,
        callback_context: CallbackContext,
        callback: SpanExportCallback(CallbackContext, Error),
    ) void {
        callback(callback_context, batch, {});
    }

    pub fn shutdown(self: *@This(), _: ?u32) !void {
        self.* = undefined;
    }

    pub fn forceFlush(_: @This(), _: ?u32) !void {}
};

pub const null_span_exporter = (NullSpanExporter{}).spanExporter(.copy);

// pub const AnySpanExporter = struct {
//     context: *anyopaque,
//     // XXX should the callback context be `*anyopaque` (not const)?
//     exportFn: *const fn (*anyopaque, []const api.AnySpan, ?u32, *const anyopaque, SpanExportCallback(*const anyopaque, Error)) void,
//     shutdownFn: *const fn (*anyopaque, ?u32) error{Timeout}!void,
//     forceFlushFn: *const fn (*anyopaque, ?u32) error{Timeout}!void,

//     pub const Error = anyerror;

//     pub const SpanExporter = trace.SpanExporter(@This(), api.AnySpan);

//     pub fn spanExporter(self: @This()) @This().SpanExporter {
//         return .{ .impl = self };
//     }

//     pub fn @"export"(
//         self: *@This(),
//         batch: []const api.AnySpan,
//         timeout_ms: ?u32,
//         comptime CallbackContext: type,
//         callback_context: CallbackContext,
//         callback: SpanExportCallback(CallbackContext, Error),
//     ) void {
//         const type_erased_callback_context: *const anyopaque = @ptrCast(callback_context);
//         const type_erased_callback: SpanExportCallback(*const anyopaque, Error) = @ptrCast(callback);
//         self.exportFn(self.context, batch, timeout_ms, type_erased_callback_context, type_erased_callback);
//     }

//     pub fn shutdown(self: *@This(), timeout_ms: ?u32) error{Timeout}!void {
//         try self.shutdownFn(self.context, timeout_ms);
//         self.* = undefined;
//     }

//     pub fn forceFlush(self: *@This(), timeout_ms: ?u32) error{Timeout}!void {
//         try self.forceFlushFn(self.context, timeout_ms);
//     }
// };

pub fn JsonSpanExporter(
    comptime Writer: type,
    /// https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/
    comptime otlp_format: bool,
) type {
    return struct {
        allocator: if (otlp_format) std.mem.Allocator else void,
        writer: Writer,
        writer_mutex: ?union(enum) {
            mutex: *std.Thread.Mutex,
            stderr,
        } = null,
        stringify_options: std.json.StringifyOptions = .{},

        pub const Error = Writer.Error || if (otlp_format) std.mem.Allocator.Error else error{};

        pub inline fn spanExporter(self: anytype, comptime iface: utils.meta.IfaceCtx) SpanExporter(iface.Type(@This())) {
            return .{ .impl = iface.context(self) };
        }

        pub fn @"export"(
            self: *@This(),
            batch: []const Span,
            _: ?u32,
            comptime CallbackContext: type,
            callback_context: CallbackContext,
            callback: SpanExportCallback(CallbackContext, Error),
        ) void {
            if (batch.len == 0) return;

            if (self.writer_mutex) |writer_mutex|
                switch (writer_mutex) {
                    .mutex => |mutex| mutex.lock(),
                    .stderr => std.debug.lockStdErr(),
                };
            defer if (self.writer_mutex) |writer_mutex|
                switch (writer_mutex) {
                    .mutex => |mutex| mutex.unlock(),
                    .stderr => std.debug.unlockStdErr(),
                };

            if (otlp_format)
                callback(callback_context, batch, err: {
                    const resource_spanss = to_otlp.batch(self.allocator, batch, false) catch |err|
                        break :err err;
                    defer {
                        for (resource_spanss) |resource_spans|
                            resource_spans.deinit();

                        self.allocator.free(resource_spanss);
                    }

                    for (resource_spanss) |resource_spans| {
                        std.json.stringify(
                            struct {
                                resource_spans: otlp.trace.ResourceSpans,

                                pub fn jsonStringify(closure: @This(), write_stream: anytype) !void {
                                    try otlp.trace.json_stringify.resourceSpans(closure.resource_spans, write_stream);
                                }
                            }{ .resource_spans = resource_spans },
                            self.stringify_options,
                            self.writer,
                        ) catch |err|
                            break :err err;
                        self.writer.writeByte('\n') catch |err|
                            break :err err;
                    }
                })
            else for (batch) |span|
                callback(callback_context, &.{span}, err: {
                    std.json.stringify(span, self.stringify_options, self.writer) catch |err|
                        break :err err;
                    self.writer.writeByte('\n') catch |err|
                        break :err err;
                });
        }

        pub fn shutdown(self: *@This(), _: ?u32) !void {
            self.* = undefined;
        }

        pub fn forceFlush(_: @This(), _: ?u32) !void {}
    };
}

pub fn jsonSpanExporter(
    writer: anytype,
    stringify_options: std.json.StringifyOptions,
) JsonSpanExporter(
    @TypeOf(writer),
    false,
) {
    return .{
        .allocator = {},
        .writer = writer,
        .stringify_options = stringify_options,
    };
}

/// https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/
pub fn otlpJsonSpanExporter(
    allocator: std.mem.Allocator,
    writer: anytype,
    stringify_options: std.json.StringifyOptions,
) JsonSpanExporter(
    @TypeOf(writer),
    true,
) {
    return .{
        .allocator = allocator,
        .writer = writer,
        .stringify_options = stringify_options,
    };
}

test jsonSpanExporter {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();

    var resource = try Resource.default(std.testing.allocator, @src().fn_name);
    defer resource.attributes.deinit(std.testing.allocator);

    var provider = tracerProvider(
        resource,
        sequentialIdGenerator(.{
            .next_trace_id = 0xDEAD,
            .next_span_id = 0xBEEF,
        }),
        simpleSpanProcessor(jsonSpanExporter(
            output.writer(),
            .{ .whitespace = .indent_2 },
        ).spanExporter(.copy)).spanProcessor(.copy),
        defaultTracerConfigurator,
        try std.heap.MemoryPool(std.atomic.Value(usize)).initPreheated(std.testing.allocator, 1),
    );
    errdefer provider.shutdown(null) catch unreachable;
    var provider_api = provider.api(.ptr);

    const tracer = provider_api.tracer(&.{ .name = @src().fn_name });
    const tracer_api = tracer.api(.const_ptr);

    var span = try testSpan(&tracer_api);
    span.setStatus(.ok);
    span.endAt(3);

    try std.testing.expectEqualStrings(
        \\{
        \\  "scope": {
        \\    "name": "decltest.jsonSpanExporter",
        \\    "version": null,
        \\    "schema_url": null,
        \\    "attributes": {}
        \\  },
        \\  "name": "test",
        \\  "context": {
        \\    "trace_id": "0000000000000000000000000000dead",
        \\    "span_id": "000000000000beef",
        \\    "trace_flags": {
        \\      "sampled": false
        \\    },
        \\    "trace_state": "",
        \\    "is_remote": false
        \\  },
        \\  "parent": null,
        \\  "kind": "internal",
        \\  "start_ns": 1,
        \\  "end_ns": 3,
        \\  "attributes": {
        \\    "foo": {
        \\      "string": "foo"
        \\    },
        \\    "bar": [
        \\      "bar1",
        \\      "bar2"
        \\    ]
        \\  },
        \\  "links": [
        \\    {
        \\      "context": {
        \\        "trace_id": "0000000000000000000000000000beef",
        \\        "span_id": "000000000000dead",
        \\        "trace_flags": {
        \\          "sampled": false
        \\        },
        \\        "trace_state": "",
        \\        "is_remote": false
        \\      },
        \\      "attributes": {
        \\        "baz": {
        \\          "string": "baz"
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "events": [
        \\    {
        \\      "name": "qux",
        \\      "timestamp_ns": 2,
        \\      "attributes": {}
        \\    }
        \\  ],
        \\  "status": {
        \\    "ok": {}
        \\  }
        \\}
        \\
    , output.items);

    try provider.shutdown(0);
}

test otlpJsonSpanExporter {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();

    var resource = try Resource.default(std.testing.allocator, @src().fn_name);
    defer resource.attributes.deinit(std.testing.allocator);

    var provider = tracerProvider(
        resource,
        sequentialIdGenerator(.{
            .next_trace_id = 0xDEAD,
            .next_span_id = 0xBEEF,
        }),
        simpleSpanProcessor(otlpJsonSpanExporter(
            std.testing.allocator,
            output.writer(),
            .{ .whitespace = .indent_2 },
        ).spanExporter(.copy)).spanProcessor(.copy),
        defaultTracerConfigurator,
        try std.heap.MemoryPool(std.atomic.Value(usize)).initPreheated(std.testing.allocator, 1),
    );
    errdefer provider.shutdown(null) catch unreachable;
    var provider_api = provider.api(.ptr);

    const tracer = provider_api.tracer(&.{ .name = @src().fn_name });
    const tracer_api = tracer.api(.const_ptr);

    var span = try testSpan(&tracer_api);
    span.setStatus(.ok);
    span.endAt(3);

    try std.testing.expectEqualStrings(
        \\{
        \\  "schemaUrl": "",
        \\  "resource": {
        \\    "attributes": [
        \\      {
        \\        "key": "service.name",
        \\        "value": {
        \\          "stringValue": "decltest.otlpJsonSpanExporter"
        \\        }
        \\      },
        \\      {
        \\        "key": "telemetry.sdk.language",
        \\        "value": {
        \\          "stringValue": "zig"
        \\        }
        \\      },
        \\      {
        \\        "key": "telemetry.sdk.name",
        \\        "value": {
        \\          "stringValue": "opentelemetry"
        \\        }
        \\      },
        \\      {
        \\        "key": "telemetry.sdk.version",
        \\        "value": {
        \\          "stringValue": "0.0.0"
        \\        }
        \\      }
        \\    ],
        \\    "droppedAttributesCount": 0
        \\  },
        \\  "scopeSpans": [
        \\    {
        \\      "scope": {
        \\        "name": "decltest.otlpJsonSpanExporter",
        \\        "version": "",
        \\        "attributes": [],
        \\        "droppedAttributesCount": 0
        \\      },
        \\      "spans": [
        \\        {
        \\          "traceId": "0000000000000000000000000000dead",
        \\          "spanId": "000000000000beef",
        \\          "traceState": "",
        \\          "parentSpanId": "",
        \\          "flags": 0,
        \\          "name": "test",
        \\          "kind": 1,
        \\          "startTimeUnixNano": 1,
        \\          "endTimeUnixNano": 3,
        \\          "attributes": [
        \\            {
        \\              "key": "foo",
        \\              "value": {
        \\                "stringValue": "foo"
        \\              }
        \\            },
        \\            {
        \\              "key": "bar",
        \\              "value": {
        \\                "arrayValue": {
        \\                  "values": [
        \\                    {
        \\                      "stringValue": "bar1"
        \\                    },
        \\                    {
        \\                      "stringValue": "bar2"
        \\                    }
        \\                  ]
        \\                }
        \\              }
        \\            }
        \\          ],
        \\          "droppedAttributesCount": 0,
        \\          "events": [
        \\            {
        \\              "timeUnixNano": 2,
        \\              "name": "qux",
        \\              "attributes": [],
        \\              "droppedAttributesCount": 0
        \\            }
        \\          ],
        \\          "droppedEventsCount": 0,
        \\          "links": [
        \\            {
        \\              "traceId": "0000000000000000000000000000beef",
        \\              "spanId": "000000000000dead",
        \\              "traceState": "",
        \\              "attributes": [
        \\                {
        \\                  "key": "baz",
        \\                  "value": {
        \\                    "stringValue": "baz"
        \\                  }
        \\                }
        \\              ],
        \\              "droppedAttributesCount": 0,
        \\              "flags": 0
        \\            }
        \\          ],
        \\          "droppedLinksCount": 0,
        \\          "status": {
        \\            "code": 1,
        \\            "message": ""
        \\          }
        \\        }
        \\      ],
        \\      "schemaUrl": ""
        \\    }
        \\  ]
        \\}
        \\
    , output.items);

    try provider.shutdown(0);
}

pub const OtlpSpanExporter = struct {
    exporter: otlp.Exporter,
    allocator: std.mem.Allocator,

    pub const Error = otlp.Exporter.ExportError;

    pub inline fn spanExporter(self: anytype, comptime iface: utils.meta.IfaceCtx) SpanExporter(iface.Type(@This())) {
        return .{ .impl = iface.context(self) };
    }

    pub fn @"export"(
        self: *@This(),
        batch: []const Span,
        timeout_ms: ?u32,
        comptime CallbackContext: type,
        callback_context: CallbackContext,
        callback: SpanExportCallback(CallbackContext, Error),
    ) void {
        callback(callback_context, batch, err: {
            const resource_spanss = to_otlp.batch(self.allocator, batch, false) catch |err|
                break :err err;
            defer {
                for (resource_spanss) |resource_spans|
                    resource_spans.deinit();

                self.allocator.free(resource_spanss);
            }

            var diagnostics: otlp.rpc.Status = undefined;
            if (self.exporter.@"export"(self.allocator, .traces, .{
                .resource_spans = std.ArrayList(otlp.trace.ResourceSpans).fromOwnedSlice(self.allocator, resource_spanss),
            }, timeout_ms, &diagnostics)) |response|
                // There is no meaningful way to handle a partial success response
                // because we don't know which spans were not accepted
                // so let's just ignore it and report success for the entire batch.
                response.deinit()
            else |err| {
                switch (err) {
                    error.ClientError, error.ServerError => {
                        defer diagnostics.deinit();

                        // Unfortunately we cannot log using `utils.fmt.fmtJsonStringify(diagnostics, .{})`
                        // because zig-protobuf can only write to `ArrayList(u8).Writer`
                        // because it needs to allocate to base64-encode strings.
                        // XXX Zig 0.14.0 added `std.base64.Base64Encoder.encodeWriter()`
                        // which could be used to fix this in zig-protobuf. Open PR?
                        const diagnostics_json = std.json.stringifyAlloc(self.allocator, diagnostics, .{}) catch |e|
                            break :err e;
                        defer self.allocator.free(diagnostics_json);
                        log.err("{s} received error response: {s}", .{ @typeName(@This()), diagnostics_json });
                    },
                    else => {},
                }
                break :err err;
            }
        });
    }

    pub fn shutdown(self: *@This(), _: ?u32) !void {
        self.exporter.deinit();
        self.* = undefined;
    }

    pub fn forceFlush(_: @This(), _: ?u32) !void {}
};

fn testSpan(tracer: anytype) !Span {
    // Must be a pointer so that the returned span does not point to stack memory.
    _ = api.Tracer(@typeInfo(@TypeOf(tracer)).pointer.child);

    var span = span: {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();

        // These leak memory when declared directly in the `SpanCreationOptions` below.
        // Probably because the compiler copies `arena` for the `span()` function parameter
        // before it calls `arena.allocator()` to construct the `attrs` and `links`.

        const attrs = api.Attributes{ .map = try api.Attributes.Map.init(
            arena.allocator(),
            &.{ "foo", "bar" },
            &.{
                .{ .one = .{ .string = "foo" } },
                .{ .many = .{ .string = std.ArrayListUnmanaged([]const u8).fromOwnedSlice(
                    try arena.allocator().dupe([]const u8, &.{ "bar1", "bar2" }),
                ) } },
            },
        ) };

        const links = try arena.allocator().dupe(api.SpanLink, &.{.{
            .context = .{
                .trace_id = .{ .bytes = std.mem.toBytes(std.mem.nativeToBig(SequentialIdGenerator.IdInt(w3c_trace_context.TraceParent.TraceId), 0xBEEF)) },
                .span_id = .{ .bytes = std.mem.toBytes(std.mem.nativeToBig(SequentialIdGenerator.IdInt(w3c_trace_context.TraceParent.ParentId), 0xDEAD)) },
            },
            .attributes = .{ .map = try api.Attributes.Map.init(
                arena.allocator(),
                &.{"baz"},
                &.{.{ .one = .{ .string = "baz" } }},
            ) },
        }});

        break :span try tracer.span(arena, "test", .{
            .start_ns = 1,
            .attributes = attrs,
            .links = std.ArrayListUnmanaged(api.SpanLink).fromOwnedSlice(links),
        });
    };
    try span.addEvent(.{ .name = "qux", .timestamp_ns = 2 });
    return span;
}

/// Functions that turn SDK types into OTLP types.
pub const to_otlp = struct {
    pub fn batch(
        allocator: std.mem.Allocator,
        spans_batch: []const Span,
        dupe: bool,
    ) std.mem.Allocator.Error![]otlp.trace.ResourceSpans {
        var map = std.AutoHashMap(
            *const Resource,
            std.AutoHashMap(
                *const api.InstrumentationScope,
                otlp.trace.ScopeSpans,
            ),
        ).init(allocator);
        defer {
            var map_iter = map.valueIterator();
            while (map_iter.next()) |scope_map|
                scope_map.deinit();

            map.deinit();
        }

        for (spans_batch) |sdk_span| {
            const gop = try map.getOrPut(sdk_span.impl.resource);
            if (!gop.found_existing)
                gop.value_ptr.* = std.AutoHashMap(
                    *const api.InstrumentationScope,
                    otlp.trace.ScopeSpans,
                ).init(allocator);

            const scope_gop = try gop.value_ptr.getOrPut(sdk_span.impl.instrumentation_scope);
            if (!scope_gop.found_existing) {
                const scope = try sdk.to_otlp.instrumentationScope(allocator, sdk_span.impl.instrumentation_scope.*, dupe);
                errdefer scope.deinit();

                const schema_url = if (sdk_span.impl.instrumentation_scope.schema_url) |schema_url|
                    protobuf.ManagedString.move(
                        try std.fmt.allocPrint(allocator, "{}", .{schema_url}),
                        allocator,
                    )
                else
                    .Empty;
                errdefer schema_url.deinit();

                scope_gop.value_ptr.* = .{
                    .scope = scope,
                    .schema_url = schema_url,
                    .spans = std.ArrayList(otlp.trace.Span).init(allocator),
                };
            }

            const otlp_span = try span(allocator, sdk_span, dupe);
            errdefer otlp_span.deinit();

            try scope_gop.value_ptr.spans.append(otlp_span);
        }

        var list = try std.ArrayListUnmanaged(otlp.trace.ResourceSpans).initCapacity(allocator, map.count());
        errdefer list.deinit(allocator);

        var map_iter = map.iterator();
        while (map_iter.next()) |map_entry| {
            const resource = try map_entry.key_ptr.*.toOtlp(allocator, dupe);
            errdefer resource.deinit();

            var scope_spanss = try std.ArrayList(otlp.trace.ScopeSpans).initCapacity(allocator, map_entry.value_ptr.count());
            errdefer scope_spanss.deinit();

            var scope_map_iter = map_entry.value_ptr.valueIterator();
            while (scope_map_iter.next()) |scope_spans|
                scope_spanss.appendAssumeCapacity(scope_spans.*);

            list.appendAssumeCapacity(.{
                .schema_url = if (map_entry.key_ptr.*.schema_url) |schema_url|
                    protobuf.ManagedString.move(
                        try std.fmt.allocPrint(allocator, "{}", .{schema_url}),
                        allocator,
                    )
                else
                    .Empty,
                .resource = resource,
                .scope_spans = scope_spanss,
            });
        }

        return list.toOwnedSlice(allocator);
    }

    pub fn span(
        allocator: std.mem.Allocator,
        sdk_span: Span,
        dupe: bool,
    ) std.mem.Allocator.Error!otlp.trace.Span {
        const trace_id = try to_otlp.traceId(allocator, sdk_span.impl.context.trace_id);
        errdefer trace_id.deinit();

        const span_id = try to_otlp.spanId(allocator, sdk_span.impl.context.span_id);
        errdefer span_id.deinit();

        const trace_state = try to_otlp.traceState(allocator, sdk_span.impl.context.trace_state);
        errdefer trace_state.deinit();

        const parent_span_id = if (sdk_span.impl.parent) |parent|
            try to_otlp.spanId(allocator, parent.span_id)
        else
            .Empty;
        errdefer parent_span_id.deinit();

        const attributes = try sdk.to_otlp.attributes(allocator, sdk_span.impl.attributes, dupe);
        errdefer attributes.deinit();

        var events = try std.ArrayList(otlp.trace.Span.Event).initCapacity(allocator, sdk_span.impl.events.items.len);
        errdefer {
            for (events.items) |event| event.deinit();
            events.deinit();
        }
        for (sdk_span.impl.events.items) |event|
            events.appendAssumeCapacity(try to_otlp.spanEvent(allocator, event, dupe));

        var links = try std.ArrayList(otlp.trace.Span.Link).initCapacity(allocator, sdk_span.impl.links.items.len);
        errdefer {
            for (links.items) |link| link.deinit();
            links.deinit();
        }
        for (sdk_span.impl.links.items) |link|
            links.appendAssumeCapacity(try to_otlp.spanLink(allocator, link, dupe));

        const name = if (dupe)
            try protobuf.ManagedString.copy(sdk_span.impl.name, allocator)
        else
            protobuf.ManagedString.managed(sdk_span.impl.name);
        errdefer name.deinit();

        const status = try to_otlp.spanStatus(allocator, sdk_span.impl.status, dupe);
        errdefer status.deinit();

        return .{
            .trace_id = trace_id,
            .span_id = span_id,
            .trace_state = trace_state,
            .parent_span_id = parent_span_id,
            .flags = sdk_span.impl.context.trace_flags.toInt(),
            .name = name,
            .kind = to_otlp.spanKind(sdk_span.impl.kind),
            .start_time_unix_nano = @truncate(@as(
                std.meta.FieldType(otlp.trace.Span, .start_time_unix_nano),
                @intCast(sdk_span.impl.start_ns),
            )),
            .end_time_unix_nano = if (sdk_span.impl.end_ns) |end_ns| @truncate(@as(
                std.meta.FieldType(otlp.trace.Span, .end_time_unix_nano),
                @intCast(end_ns),
            )) else 0,
            .attributes = attributes.values,
            .dropped_attributes_count = 0,
            .events = events,
            .dropped_events_count = 0,
            .links = links,
            .dropped_links_count = 0,
            .status = status,
        };
    }

    pub fn spanKind(kind: api.SpanKind) otlp.trace.Span.SpanKind {
        return switch (kind) {
            .internal => .SPAN_KIND_INTERNAL,
            .server => .SPAN_KIND_SERVER,
            .client => .SPAN_KIND_CLIENT,
            .producer => .SPAN_KIND_PRODUCER,
            .consumer => .SPAN_KIND_CONSUMER,
        };
    }

    pub fn spanStatus(
        allocator: std.mem.Allocator,
        status: api.SpanStatus,
        dupe: bool,
    ) std.mem.Allocator.Error!otlp.trace.Status {
        return .{
            .message = switch (status) {
                .@"error" => |msg| if (dupe)
                    try protobuf.ManagedString.copy(msg, allocator)
                else
                    protobuf.ManagedString.managed(msg),
                .unset, .ok => .Empty,
            },
            .code = switch (status) {
                .unset => .STATUS_CODE_UNSET,
                .ok => .STATUS_CODE_OK,
                .@"error" => .STATUS_CODE_ERROR,
            },
        };
    }

    pub fn spanEvent(
        allocator: std.mem.Allocator,
        event: api.SpanEvent,
        dupe: bool,
    ) std.mem.Allocator.Error!otlp.trace.Span.Event {
        const name = if (dupe)
            try protobuf.ManagedString.copy(event.name, allocator)
        else
            protobuf.ManagedString.managed(event.name);
        errdefer name.deinit();

        const attributes = try sdk.to_otlp.attributes(allocator, event.attributes, dupe);
        errdefer attributes.deinit();

        return .{
            .time_unix_nano = @truncate(@as(u64, @intCast(event.timestamp_ns))),
            .name = name,
            .attributes = attributes.values,
            .dropped_attributes_count = 0,
        };
    }

    pub fn spanLink(
        allocator: std.mem.Allocator,
        link: api.SpanLink,
        dupe: bool,
    ) std.mem.Allocator.Error!otlp.trace.Span.Link {
        const trace_id = try traceId(allocator, link.context.trace_id);
        errdefer trace_id.deinit();

        const span_id = try spanId(allocator, link.context.span_id);
        errdefer span_id.deinit();

        const trace_state = try traceState(allocator, link.context.trace_state);
        errdefer trace_state.deinit();

        const attributes = try sdk.to_otlp.attributes(allocator, link.attributes, dupe);
        errdefer attributes.deinit();

        return .{
            .trace_id = trace_id,
            .span_id = span_id,
            .trace_state = trace_state,
            .attributes = attributes.values,
            .dropped_attributes_count = 0,
            .flags = link.context.trace_flags.toInt(),
        };
    }

    pub fn traceId(allocator: std.mem.Allocator, trace_id: w3c_trace_context.TraceParent.TraceId) std.mem.Allocator.Error!protobuf.ManagedString {
        return protobuf.ManagedString.copy(
            &trace_id.bytes,
            allocator,
        );
    }

    pub fn spanId(allocator: std.mem.Allocator, span_id: w3c_trace_context.TraceParent.ParentId) std.mem.Allocator.Error!protobuf.ManagedString {
        return protobuf.ManagedString.copy(
            &span_id.bytes,
            allocator,
        );
    }

    pub fn traceState(allocator: std.mem.Allocator, trace_state: api.TraceState) std.mem.Allocator.Error!protobuf.ManagedString {
        return protobuf.ManagedString.move(
            try std.fmt.allocPrint(allocator, "{}", .{trace_state}),
            allocator,
        );
    }
};

test {
    std.testing.refAllDeclsRecursive(@This());
}

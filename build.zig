const std = @import("std");
const protobuf = @import("protobuf");
const utils = @import("utils").utils;

const Build = std.Build;

pub fn build(b: *Build) !void {
    const options = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const w3c_baggage_mod = b.addModule("w3c-baggage", .{
        .root_source_file = b.path("src/w3c/baggage.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "utils", .module = b.dependency("utils", options).module("utils") },
        },
    });
    _ = w3c_baggage_mod; // autofix

    const w3c_trace_context_mod = b.addModule("w3c-trace-context", .{
        .root_source_file = b.path("src/w3c/trace-context.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "utils", .module = b.dependency("utils", options).module("utils") },
        },
    });

    const otlp_mod = otlp_mod: {
        var protoc_wf = b.addWriteFiles();
        var protoc_step = protobuf.RunProtocStep.create(
            b,
            b.dependency("protobuf", options).builder,
            options.target,
            .{
                .destination_directory = protoc_wf.getDirectory(),
                .source_files = &.{
                    "opentelemetry/proto/collector/trace/v1/trace_service.proto",
                    "opentelemetry/proto/trace/v1/trace.proto",
                    "opentelemetry/proto/trace/v1/trace.proto",
                    "google/rpc/status.proto",
                },
                .include_directories = &.{
                    b.dependency("opentelemetry-proto", .{}).path("").getPath(b),
                    b.dependency("googleapis", .{}).path("").getPath(b),
                },
            },
        );
        protoc_step.verbose = b.verbose;
        protoc_step.step.dependOn(&protoc_wf.step);

        var mod_wf = b.addWriteFiles();
        mod_wf.step.dependOn(&protoc_step.step);
        _ = mod_wf.addCopyDirectory(protoc_wf.getDirectory(), "", .{});

        break :otlp_mod b.addModule("otlp", .{
            .root_source_file = mod_wf.addCopyFile(b.path("src/otlp.zig"), "root.zig"),
            .target = options.target,
            .optimize = options.optimize,
            .imports = &.{
                .{ .name = "protobuf", .module = b.dependency("protobuf", options).module("protobuf") },
                .{ .name = "utils", .module = b.dependency("utils", options).module("utils") },
                .{ .name = "retry", .module = b.dependency("retry", options).module("retry") },
            },
        });
    };

    const api_mod = b.addModule("api", .{
        .root_source_file = b.path("src/api.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "w3c-trace-context", .module = w3c_trace_context_mod },

            .{ .name = "utils", .module = b.dependency("utils", options).module("utils") },
        },
    });

    _ = b.addModule("sdk", .{
        .root_source_file = b.path("src/sdk.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "w3c-trace-context", .module = w3c_trace_context_mod },
            .{ .name = "api", .module = api_mod },
            .{ .name = "otlp", .module = otlp_mod },

            .{ .name = "protobuf", .module = b.dependency("protobuf", options).module("protobuf") },
            .{ .name = "utils", .module = b.dependency("utils", options).module("utils") },
        },
    });

    const test_step = b.step("test", "Run unit tests");
    inline for (.{ "w3c-baggage", "w3c-trace-context", "api", "sdk", "otlp" }) |mod_name| {
        const mod = b.modules.get(mod_name).?;

        const mod_test = utils.addModuleTest(b, mod, .{
            .name = mod_name,
        });

        const run_mod_test = b.addRunArtifact(mod_test);
        test_step.dependOn(&run_mod_test.step);
    }

    _ = utils.addCheckTls(b);
}

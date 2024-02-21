const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const keylib_dep = b.dependency("keylib", .{
        .target = target,
        .optimize = optimize,
    });

    const hidapi_dep = b.dependency("hidapi", .{
        .target = target,
        .optimize = optimize,
    });

    // Authenticator

    const exe = b.addExecutable(.{
        .name = "authenticator",
        .root_source_file = .{ .path = "src/authenticator.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("keylib", keylib_dep.module("keylib"));
    exe.addModule("uhid", keylib_dep.module("uhid"));
    exe.addModule("zbor", keylib_dep.module("zbor"));
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run-auth", "Run the authenticator");
    run_step.dependOn(&run_cmd.step);

    // Client

    const exe2 = b.addExecutable(.{
        .name = "client",
        .root_source_file = .{ .path = "src/client.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe2.addModule("keylib", keylib_dep.module("keylib"));
    exe2.addModule("zbor", keylib_dep.module("zbor"));
    exe2.linkLibrary(hidapi_dep.artifact("hidapi"));
    exe2.linkSystemLibrary("curl");
    exe2.linkLibC();

    b.installArtifact(exe2);

    const run_cmd2 = b.addRunArtifact(exe2);

    run_cmd2.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step2 = b.step("run-client", "Run the client");
    run_step2.dependOn(&run_cmd2.step);

    const client_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/client.zig" },
        .target = target,
        .optimize = optimize,
    });

    const client_test_step = b.step("test", "Run client tests");
    client_test_step.dependOn(&b.addRunArtifact(client_tests).step);

    // app

    const exe3 = b.addExecutable(.{
        .name = "app",
        .root_source_file = .{ .path = "src/app.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe3.addModule("keylib", keylib_dep.module("keylib"));
    exe3.addModule("zbor", keylib_dep.module("zbor"));
    exe3.linkLibrary(hidapi_dep.artifact("hidapi"));
    exe3.linkLibC();

    b.installArtifact(exe3);
}

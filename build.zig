const std = @import("std");

pub fn build(b: *std.Build) !void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const exe = b.addExecutable(.{
        .root_source_file = b.path("main.zig"),
        .name = "keypit",
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(exe);
}

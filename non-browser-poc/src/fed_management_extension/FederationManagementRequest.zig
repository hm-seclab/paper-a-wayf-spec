//! This file contains the request data structure for
//! a authenticatorFederationManagement command proposed
//! by A-WAYF.
const std = @import("std");
const cbor = @import("zbor");
const fido = @import("keylib");

subCommand: SubCommand,
/// PIN/UV protocol version chosen by the platform
pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol = null,
/// First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken
pinUvAuthParam: ?[]const u8 = null,

/// List of sub commands for federation management
pub const SubCommand = enum(u8) {
    enumerateIdPBegin = 0x01,
    enumerateIdPsGetNextIdP = 0x02,
};

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .field_settings = &.{
            .{ .name = "subCommand", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
        },
        .from_callback = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_callback = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "subCommand", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
        },
    });
}

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.pinUvAuthParam) |p| {
        allocator.free(p);
    }
}

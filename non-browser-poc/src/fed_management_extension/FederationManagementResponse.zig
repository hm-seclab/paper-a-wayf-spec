const std = @import("std");
const cbor = @import("zbor");
const fido = @import("keylib");

idp: ?[]const u8 = null,
totalIdps: ?u32 = null,

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .field_settings = &.{
            .{ .name = "idp", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
            .{ .name = "totalIdps", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
        },
        .from_callback = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_callback = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "idp", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
            .{ .name = "totalIdps", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
        },
    });
}

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.idp) |idp| {
        allocator.free(idp);
    }
}

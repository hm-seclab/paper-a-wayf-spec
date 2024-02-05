const std = @import("std");
const cbor = @import("zbor");
const keylib = @import("keylib");

const client = keylib.client;
const Transport = client.Transports.Transport;
const commands = client.cbor_commands;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main() !void {
    // Get all devices connect to the platform
    var transports = try client.Transports.enumerate(allocator, .{});
    defer transports.deinit();

    // Choose a device
    if (transports.devices.len == 0) {
        std.log.err("No device found, exiting...", .{});
        return;
    }

    var device = &transports.devices[0];
    try device.open();
    defer device.close();

    var idp = try fedManaement.enumerateIdPBegin(device, allocator);
    if (idp) |idp_| {
        defer idp_.deinit();
        std.log.info("[0]: {s}, {d}", .{ idp_.idp, idp_.total.? });
    } else {
        std.log.warn("no valid IdP found", .{});
        return;
    }
}

pub const fedManaement = struct {
    pub const IdPResponse = struct {
        idp: []const u8,
        total: ?u32 = null,
        a: std.mem.Allocator,

        pub fn deinit(self: *const @This()) void {
            self.a.free(self.idp);
        }
    };

    const FederationManagementRequest = @import("fed_management_extension/FederationManagementRequest.zig");
    const FederationManagementResponse = @import("fed_management_extension/FederationManagementResponse.zig");

    pub fn enumerateIdPBegin(
        t: *Transport,
        a: std.mem.Allocator,
    ) !?IdPResponse {
        const request = FederationManagementRequest{
            .subCommand = .enumerateIdPBegin,
        };

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(0x42);
        try cbor.stringify(request, .{}, arr.writer());

        try t.write(arr.items);

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0xe1) {
                return null; // no IdPs found
            }

            if (response[0] != 0) {
                return client.err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(FederationManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.idp == null) {
                // this is somewhat an edge case, maybe
                // whe should return an error instead.
                return null;
            }

            return IdPResponse{
                .idp = try a.dupe(u8, r.idp.?),
                .total = if (r.totalIdps) |tot| tot else 1,
                .a = a,
            };
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateIdPsGetNextIdP() void {}
};

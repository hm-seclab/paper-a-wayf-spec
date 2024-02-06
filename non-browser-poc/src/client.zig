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
        defer idp_.deinit(allocator);
        std.log.info("[0]: {s}, {s}, {d}", .{ idp_.idpId.?, idp_.rpId.?, idp_.totalIdps.? });
    } else {
        std.log.warn("no valid IdP found", .{});
        return;
    }
}

pub const fedManaement = struct {
    const FederationManagementRequest = @import("fed_management_extension/FederationManagementRequest.zig");
    const FederationManagementResponse = @import("fed_management_extension/FederationManagementResponse.zig");

    pub fn enumerateIdPBegin(
        t: *Transport,
        a: std.mem.Allocator,
    ) !?FederationManagementResponse {
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
            errdefer r.deinit(a);

            if (r.rpId == null or r.idpId == null) {
                return error.MissingField;
            }

            return r;
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateIdPsGetNextIdP() void {}
};

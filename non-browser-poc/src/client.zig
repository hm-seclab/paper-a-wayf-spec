const std = @import("std");
const cbor = @import("zbor");
const keylib = @import("keylib");

const client = keylib.client;
const Transport = client.Transports.Transport;
const commands = client.cbor_commands;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main() !void {
    _ = try navigator.credential.resolveWAYF(
        &.{ "sso.hm.edu", "idp.orga.edu", "idp.orgb.edu" },
        &.{ &.{ "sp.orga.edu", "fake-org.net" }, &.{ "sp.orga.edu", "orga.edu", "hm.edu" } },
        "OIDfed",
    );
}

pub const navigator = struct {
    pub const credential = struct {
        /// Execute a A-WAYF process.
        ///
        /// # Arguments
        ///
        /// * `idp_list` - List of supported IdPs, e.g., ["idp.orga.edu", "idp.orgb.edu"].
        /// * `trust_statements` - List of JSON Web Tokens that build a trust chain.
        /// * `fed_protocol` - Federation protocol to use, e.g., "OIDfed".
        ///
        /// # Returns
        ///
        /// TODO
        pub fn resolveWAYF(
            idp_list: fedManagement.IdPList,
            trust_statements: fedManagement.TrustStatements,
            fed_protocol: []const u8,
        ) !?[]const u8 {
            _ = idp_list;
            _ = trust_statements;
            _ = fed_protocol;

            // ##########################################
            // Step 2 -  Credentials Enumeration
            // ##########################################

            // Get all devices connect to the platform
            var transports = try client.Transports.enumerate(allocator, .{});
            defer transports.deinit();

            // Choose a device
            if (transports.devices.len == 0) {
                std.log.err("No device found, exiting...", .{});
                return null;
            }

            var device = &transports.devices[0];
            try device.open();
            defer device.close();

            var idp = try fedManagement.enumerateIdPBegin(device, allocator);
            if (idp) |idp_| {
                defer idp_.deinit(allocator);
                std.log.info("[0]: {s}, {s}, {d}", .{ idp_.idpId.?, idp_.rpId.?, idp_.totalIdps.? });
            } else {
                std.log.warn("no valid IdP found", .{});
                return null;
            }

            // ##########################################
            // Step 3 – Trusted IdP Selection
            // ##########################################

            // Step 3.1 – IdP Matching:

            // Step 3.2 – Trust Resolve:

            return null;
        }
    };
};

pub const fedManagement = struct {
    const FederationManagementRequest = @import("fed_management_extension/FederationManagementRequest.zig");
    pub const FederationManagementResponse = @import("fed_management_extension/FederationManagementResponse.zig");
    pub const IdPList = []const []const u8;
    pub const TrustStatements = []const []const []const u8; // TODO: implement support of JSON Web Tokens

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

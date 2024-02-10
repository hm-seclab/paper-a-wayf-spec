const std = @import("std");
const cbor = @import("zbor");
const keylib = @import("keylib");

const client = keylib.client;
const Transport = client.Transports.Transport;
const commands = client.cbor_commands;

const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const client_pin = client.cbor_commands.client_pin;
const cred_management = client.cbor_commands.cred_management;
const Info = client.cbor_commands.Info;

pub const PinUvAuth = keylib.ctap.pinuv.PinUvAuth;
pub const ClientPin = keylib.ctap.request.ClientPin;
pub const ClientPinResponse = keylib.ctap.response.ClientPin;
pub const EcdhP256 = keylib.ctap.crypto.dh.EcdhP256;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main() !void {
    // We instruct our client to navigate to the FedSP hosted at sp.orga.edu

    // The FedSP uses navigator.credential.resolveWAY
    _ = try navigator.credential.resolveWAYF(
        &.{ "sso.hm.edu", "idp.orga.edu", "idp.orgb.edu" },
        // NOTE: In reality, the trust_statements parameter contains a set of JSON Web Tokens (JWTs).
        //       We only use the chains entity IDs here for clarity.
        &.{ &.{ "sp.orga.edu", "fake-org.net" }, &.{ "sp.orga.edu", "orga.edu", "hm.edu" } },
        "OIDfed",
        allocator,
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
            a: std.mem.Allocator,
        ) !?[]const u8 {
            _ = idp_list;
            _ = trust_statements;

            // ##########################################
            // Step 2 -  Credentials Enumeration
            // ##########################################

            // Select a device from all available devices
            // ------------------------------------------
            var transports = try client.Transports.enumerate(a, .{});
            defer transports.deinit();

            if (transports.devices.len == 0) {
                std.log.err("No device found, exiting...", .{});
                return null;
            }

            var device = &transports.devices[0];
            try device.open();
            defer device.close();

            // Verify that the selected device posesses the required capabilities
            // ------------------------------------------------------------------
            const infos = try (try authenticatorGetInfo(device)).@"await"(a);
            defer infos.deinit(a);
            const info = try infos.deserializeCbor(Info, a);
            defer info.deinit(a);

            if (!info.extensionSupported("federationId")) {
                std.log.warn("The given device doesn't support the federationId extension", .{});
                return null;
            }

            if (info.options.clientPin == null and info.options.uv == null) {
                std.log.err("The selected device doesn't support user verification", .{});
                return null;
            }

            // Obtain a pinUvAuthToken
            // -----------------------
            var op: ?[]const u8 = null;

            // We prefer internal uv over pin
            if (info.options.uv != null and info.options.uv.?) {
                if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
                    op = "getPinUvAuthTokenUsingUvWithPermissions";
                }
            }

            if (op == null) {
                if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
                    if (info.options.clientPin != null and info.options.clientPin.?) {
                        op = "getPinUvAuthTokenUsingPinWithPermissions";
                    }
                } else {
                    if (info.options.clientPin != null and info.options.clientPin.?) {
                        op = "getPinToken";
                    }
                }
            }

            if (op == null) {
                std.log.err("Selected authenticator doesn't support pinUvAuthToken", .{});
                return null;
            }

            if (info.pinUvAuthProtocols == null) {
                std.log.err("Device supports user verification but no pinUvAuthProtocols were returned as a result of calling getInfo", .{});
                return null;
            }
            const pinUvAuthProtocol = info.pinUvAuthProtocols.?[0];

            // get a shared secret
            var enc = try client_pin.getKeyAgreement(device, pinUvAuthProtocol, a);
            defer enc.deinit();

            const pw = "1234"; // TODO: make this interactive

            const token = if (std.mem.eql(u8, op.?, "getPinToken")) blk: {
                break :blk try client_pin.getPinToken(device, &enc, pw[0..], a);
            } else if (std.mem.eql(u8, op.?, "getPinUvAuthTokenUsingUvWithPermissions")) blk: {
                break :blk try client_pin.getPinUvAuthTokenUsingUvWithPermissions(
                    device,
                    &enc,
                    .{ .reserved1 = 1 }, // 0x40 fedId
                    null, // no rpId
                    a,
                );
            } else blk: {
                break :blk try a.dupe(u8, "\xca\xfe\xba\xbe\xca\xfe\xba\xbe\xca\xfe\xba\xbe\xca\xfe\xba\xbe\xca\xfe\xba\xbe\xca\xfe\xba\xbe\xca\xfe\xba\xbe\xca\xfe\xba\xbe"); // here we would return a token generated via getPinUvAuthTokenUsingPinWithPermissions
            };
            defer a.free(token);

            // Enumerate all available IdPs
            // ----------------------------
            var idp_list2 = std.ArrayList(fedManagement.FederationManagementResponse).init(a);
            defer {
                for (idp_list2.items) |elem| {
                    elem.deinit(a);
                }
                idp_list2.deinit();
            }

            // The client calls the authenticatorFederationManagement function
            var idp = try fedManagement.enumerateIdPBegin(
                device,
                pinUvAuthProtocol,
                token,
                a,
            );
            if (idp) |idp_| {
                var i: usize = 0;
                const total = idp_.totalIdps.?;

                std.log.info("[{d}]: {s}, {d}", .{ i, idp_.idpId.?, total });
                try idp_list2.append(idp_);
                i += 1;

                while (i < total) : (i += 1) blk: {
                    idp = try fedManagement.enumerateIdPsGetNextIdP(device, a);

                    if (idp) |idp__| {
                        std.log.info("[{d}]: {s}", .{ i, idp__.idpId.? });
                        try idp_list2.append(idp__);
                    } else {
                        std.log.warn("expected {d} IdPs but got {d}", .{ total, i });
                        break :blk;
                    }
                }
            } else {
                std.log.warn("no valid IdP found", .{});
                return null;
            }

            // ##########################################
            // Step 3 – Trusted IdP Selection
            // ##########################################

            if (std.mem.eql(u8, "OIDfed", fed_protocol)) {
                // TODO: We need to implement JWT otherwise we can't really demonstrate what
                // it means when we write "In our PoC, the signature by fake-org.net is invalid, therefore the validation fails."

                // Also, this setp requires some GET and POST requests (e.g. using CURL). I should
                // implement this with Erwin as he implements the server.
            } else {
                std.log.err("unsupported federation protocol {s}", .{fed_protocol});
                return null;
            }

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
        protocol: keylib.ctap.pinuv.common.PinProtocol,
        param: []const u8,
        a: std.mem.Allocator,
    ) !?FederationManagementResponse {
        const _param = switch (protocol) {
            .V1 => try PinUvAuth.authenticate_v1(param, "\x01", a),
            .V2 => try PinUvAuth.authenticate_v2(param, "\x01", a),
        };
        defer a.free(_param);

        const request = FederationManagementRequest{
            .subCommand = .enumerateIdPBegin,
            .pinUvAuthProtocol = protocol,
            .pinUvAuthParam = _param,
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

            if (r.idpId == null or r.totalIdps == null) {
                return error.MissingField;
            }

            return r;
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateIdPsGetNextIdP(
        t: *Transport,
        a: std.mem.Allocator,
    ) !?FederationManagementResponse {
        const request = FederationManagementRequest{
            .subCommand = .enumerateIdPsGetNextIdP,
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

            if (r.idpId == null) {
                return error.MissingField;
            }

            return r;
        } else {
            return error.MissingResponse;
        }
    }
};

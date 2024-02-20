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

const jwt = @import("jwt.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main() !void {
    // TODO: get the trust chain from an endpoint
    const sp_strust_chain =
        \\ [
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iXSwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAiazZBVzN2T3k3NXhYb2NfR2daSnFOck9Qc2ZrbmZwaHFNSXRmQnNPM2ZUNCIsInkiOiAiMTNBWTllRDV5cjAxMG9pYjN2Q0FFbjliYmxVajFETVNTM09oVEt3ME1IQSIsImtpZCI6ICJOVGxoTVRaaE9HRmlNalZqTXpFd1pEY3dZV00xTWpCbE1qSTNNbU5qT1RrNE1XVTJPV00yTkRnek9HUTRZbUppT1RJM00yRXpaVEJpTURNME9XRTNOdyJ9XX0sImlzcyI6ICJzcC5lZHUiLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ.YcqT1kx4Dwz8sQV2dUN9wOCU85O7jOruYaLZSuU19YYAF6IUMi8Cl6tjUtKlo2YK6_bZrWJcIqgfIloWfkX6mw",
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiWVdObE16QmlOREkzTjJFek1ETXlaamcxTW1JeVpUWXdZMkpqWVdKbE5tVmlOamMwTkdWbVptSTFPV1V6TmpsaE16UXdNek5tTURBMk9UVmtPREZoWmcifQ.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJpbnQuY29tIl0sImp3a3MiOiB7ImtleXMiOiBbeyJrdHkiOiAiRUMiLCJjcnYiOiAiUC0yNTYiLCJ4IjogIms2QVczdk95NzV4WG9jX0dnWkpxTnJPUHNma25mcGhxTUl0ZkJzTzNmVDQiLCJ5IjogIjEzQVk5ZUQ1eXIwMTBvaWIzdkNBRW45YmJsVWoxRE1TUzNPaFRLdzBNSEEiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifV19LCJpc3MiOiAiaW50LmVkdSIsImlhdCI6IDE3MDgxMTgyMTEsImV4cCI6IDE3MDgyMDQ2MTF9.MhNac4cLhBhXHTSSRaJ25tpMjhzUMYbA0ptLXwaQtfzikM-UmfSc6W7zhfApnWSugR8iyfgdaHFXz8BtyKkb6w",
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTUdKbVltTTRObUZtWkRKaU1EUXdZbUZpTVdNelpHRTBNRGs1TnpReFptUXhaak5qTkRrMk1EYzNaRFpqTnpjMll6STBPRFJrWlRJNU5UazBNV0l5WlEifQ.eyJzdWIiOiAiaW50LmVkdSIsImF1dGhvcml0eV9oaW50cyI6IFsidGEuY29tIl0sImp3a3MiOiB7ImtleXMiOiBbeyJrdHkiOiAiRUMiLCJjcnYiOiAiUC0yNTYiLCJ4IjogInBFWEFUcUc5NnN4MVRTLXhqRE9Jb1BWZEZULWdpRW1vZF9pVVZRX0JBZjgiLCJ5IjogImZRbjVEZVIwb01FNWRYdFBVNk92Q1BOa2ZtUXI3dkJkUjBRV3pJajBKbFEiLCJraWQiOiAiWVdObE16QmlOREkzTjJFek1ETXlaamcxTW1JeVpUWXdZMkpqWVdKbE5tVmlOamMwTkdWbVptSTFPV1V6TmpsaE16UXdNek5tTURBMk9UVmtPREZoWmcifV19LCJpc3MiOiAidGEuY29tIiwiaWF0IjogMTcwODExODIxMSwiZXhwIjogMTcwODIwNDYxMX0.6neU5p0RPWg1BiB5nNheb4OZD6xxLmblPEWak7YtwNc8l2J7tAB28zTbOnQlsaaC_vG_A5Dr-0deyGf4Vh8M9Q",
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTUdKbVltTTRObUZtWkRKaU1EUXdZbUZpTVdNelpHRTBNRGs1TnpReFptUXhaak5qTkRrMk1EYzNaRFpqTnpjMll6STBPRFJrWlRJNU5UazBNV0l5WlEifQ.eyJzdWIiOiAidGEuY29tIiwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAicGJoV2RNYVE2cDk3YWpGY2V1S0ZKa2RmY21IZGtqekZocDFheXBvSFpsYyIsInkiOiAiUmZiS05RbkhvR1VrVXA0aDhGel9jRFNPVmRrNlJOYkIwbVI1N25OLUR6VSIsImtpZCI6ICJNR0ptWW1NNE5tRm1aREppTURRd1ltRmlNV016WkdFME1EazVOelF4Wm1ReFpqTmpORGsyTURjM1pEWmpOemMyWXpJME9EUmtaVEk1TlRrME1XSXlaUSJ9XX0sImlzcyI6ICJ0YS5jb20iLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ.2iNX2fH4TLteeWzJO7QevgJxHGP09OLu7iYVeYwgggrxng7d78Vpjb9Xv5X3q48PEv7Sb9m7bL5UW1YBNqLz0g"
        \\ ]
    ;

    // The trust chain is supplied by the service provider (SP).
    //
    // In this example the SP and client are the same entity. This is a perfectly conceivable scenario.
    // One example could be a conferencing application installed on the users PC that allows federated authentication.
    // For web applications, the client (browser) has to implements resolveWAYF() as web application MUST NOT get direct
    // access to an authenticator.
    const tc = try std.json.parseFromSliceLeaky(jwt.TrustChain, allocator, sp_strust_chain, .{ .allocate = .alloc_always });
    defer {
        for (tc) |ec| {
            allocator.free(ec);
        }
        allocator.free(tc);
    }

    // This function will derive an identity provider (IdP) for us.
    _ = try navigator.credential.resolveWAYF(
        // It takes a list of supported IdPs...
        &.{ "sso.hm.edu", "idp.orga.edu", "idp.orgb.edu" },
        // ...the trust chain of the SP...
        tc,
        // ...and the federation protocol to expect.
        "OIDfed",
        allocator,
    );

    // The next step would be to direct the user to the given IdP for authentication.
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
            trust_chain: jwt.TrustChain,
            fed_protocol: []const u8,
            a: std.mem.Allocator,
        ) !?[]const u8 {
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

                //std.log.info("[{d}]: {s}, {d}", .{ i, idp_.idpId.?, total });
                try idp_list2.append(idp_);
                i += 1;

                while (i < total) : (i += 1) blk: {
                    idp = try fedManagement.enumerateIdPsGetNextIdP(device, a);

                    if (idp) |idp__| {
                        //std.log.info("[{d}]: {s}", .{ i, idp__.idpId.? });
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

            // Step 3.1 – IdP Matching: Here we remove all IdPs that are not supported.
            var potential_idps = std.ArrayList([]const u8).init(a);
            defer potential_idps.deinit();

            outer: for (idp_list2.items) |item1| {
                for (idp_list) |item2| {
                    if (std.mem.eql(u8, item1.idpId.?, item2)) {
                        // We just reuse the pointer to the item in idp_list2
                        try potential_idps.append(item1.idpId.?);
                        continue :outer;
                    }
                }
            }

            // Step 3.2 – Trust Resolve:

            // First we have to verify that the TC of the SP is valid.
            // TODO: As the TC is hardcoded we have to use a static time stamp.
            try jwt.validateTrustChain(trust_chain, 1708118300, a);

            // Next, for all available IdPs we have to:
            //     a) query the trust chain and verify it
            //     b) mutually verify the TA provided by the SP and the TA queried for the IdP
            // The idea behind b) is that while the first TC is controlled by the SP (i.e. not trust worthy)
            // the second TC has been queried by the client which we trust. For desktop/mobile
            // applications where client and SP are the same entity, we assume that the
            // appication itself is trust worthy (the user had to proactively install it).
            // TODO

            // Return selected IdP

            if (idp_list2.items.len == 0) return null;

            std.log.info("Please select an identity provider to authenticate with:", .{});
            for (potential_idps.items, 0..) |item, i| {
                std.log.info("    [{d}] {s}", .{ i, item });
            }

            return null;
        }
    };
};

pub const fedManagement = struct {
    const FederationManagementRequest = @import("fed_management_extension/FederationManagementRequest.zig");
    pub const FederationManagementResponse = @import("fed_management_extension/FederationManagementResponse.zig");
    pub const IdPList = []const []const u8;

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

test "client tests" {
    _ = jwt;
}

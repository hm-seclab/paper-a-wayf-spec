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

const stdout = std.io.getStdOut();
const stdin = std.io.getStdIn();

const jwt = @import("jwt.zig");

const cURL = @cImport({
    @cInclude("curl/curl.h");
});

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();
var in_buffer: [100]u8 = undefined;
pub var verbose = false;

const sp_token = @embedFile("resolve-sp");
const idp_token = @embedFile("resolve-idp");

pub fn main() !void {
    var args = std.process.args();
    _ = args.skip();
    const flag = args.next();
    if (flag != null and std.mem.eql(u8, "-v", flag.?)) {
        verbose = true;
    }

    // global curl init, or fail
    if (cURL.curl_global_init(cURL.CURL_GLOBAL_ALL) != cURL.CURLE_OK)
        return error.CURLGlobalInitFailed;
    defer cURL.curl_global_cleanup();

    const statement = try jwt.JWS.fromSlice(sp_token, allocator);
    defer statement.deinit(allocator);

    if (statement.payload.trust_chain == null) {
        return error.MissingTrustChain;
    }

    // The trust chain is supplied by the service provider (SP).
    //
    // In this example the SP and client are the same entity. This is a perfectly conceivable scenario.
    // One example could be a conferencing application installed on the users PC that allows federated authentication.
    // For web applications, the client (browser) has to implements resolveWAYF() as web applications MUST NOT get direct
    // access to an authenticator due to privacy and security considerations.
    //const tc = try std.json.parseFromSliceLeaky(jwt.TrustChain, allocator, statement.payload.trust_chain.?, .{ .allocate = .alloc_always });
    //defer {
    //    for (tc) |ec| {
    //        allocator.free(ec);
    //    }
    //    allocator.free(tc);
    //}

    try stdout.writeAll("Welcome to the A-WAYF demo.\nDo you want to resolve an IdP based on passkeys? [Y/n]: ");
    const answer = (try nextLine(stdin.reader(), &in_buffer)).?;

    if (answer.len == 0 or answer[0] != 'Y' and answer[0] != 'y') return;

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Initial Service Access (1)
    //
    // The service provider wants to start an authentication
    // process. Therefor, he uses resolveWAYF() to derive
    // the IdP to use for authentication.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    // This function will derive an identity provider (IdP) for us.
    const idp = try navigator.credential.resolveWAYF(
        // It takes a list of supported IdPs...
        &.{ "sso.hm.edu", "idp.orga.edu", "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/", "http://op.a-wayf.local:8002/oidc/op", "idp.orgb.edu" },
        // ...the trust chain of the SP...
        statement.payload.trust_chain.?,
        // ...and the federation protocol to expect.
        "OIDfed",
        allocator,
    );
    defer {
        if (idp) |idp_| {
            allocator.free(idp_);
        }
    }

    if (idp) |idp_| {
        try std.fmt.format(stdout.writer(), "Redirecting to {s} for authentication\n", .{idp_});
    } else {
        try stdout.writeAll("No valid IdP found\n");
    }

    // The next step would be to direct the user to the given IdP for authentication.
}

fn nextLine(reader: anytype, buffer: []u8) !?[]const u8 {
    var line = (try reader.readUntilDelimiterOrEof(
        buffer,
        '\n',
    )) orelse return null;
    // trim annoying windows-only carriage return character
    if (@import("builtin").os.tag == .windows) {
        return std.mem.trimRight(u8, line, "\r");
    } else {
        return line;
    }
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
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // IdP Enumeration (2)
            //
            // First we select an authenticator and fetch all
            // IdPs available.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

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

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // IdP Matching (3)
            //
            // Here we create a new set which is the intersection of
            // the IdPs gathered from the authenticator and the IdPs
            // passed to resolveWAYF().
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

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

            if (idp_list2.items.len == 0) return null;

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Trust Resolve (4)
            //
            // To prevent potential misuse where malicious SPs attempt to deceive users
            // into revealing their affiliation, the browser must determine whether the
            // user’s HomeIdP and the FedSP are members of the same federation. Therefore,
            // the list of candidate IdPs and the set of TS previously supplied to the
            // browser by the FedSP is used to verify this trust relationship.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

            if (std.mem.eql(u8, "OIDfed", fed_protocol)) {
                // First we have to verify that the TC of the SP is valid.
                // TODO: As the TC is hardcoded we have to use a static time stamp.
                jwt.validateTrustChain(trust_chain, std.time.timestamp(), a) catch |e| {
                    std.log.err("SP trust chain invalid ({any})", .{e});
                    return null;
                };

                // Next, for all available IdPs we have to:
                //     a) query the trust chain and verify it
                //     b) mutually verify the TA provided by the SP and the TA queried for the IdP
                // The idea behind b) is that while the first TC is controlled by the SP (i.e. not trust worthy)
                // the second TC has been queried by the client which we trust. For desktop/mobile
                // applications where client and SP are the same entity, we assume that the
                // appication itself is trust worthy (the user had to proactively install it).

                var valid_idps = std.ArrayList([]const u8).init(a);
                defer valid_idps.deinit();
                for (potential_idps.items) |IdP| {
                    const jws = resolveTrustChain2(IdP, a) catch |e| {
                        std.log.warn("unable to fetch trust chain for {s} ({any}). Removing entry...", .{ IdP, e });
                        continue;
                    };
                    defer jws.deinit(a);

                    if (verbose)
                        std.log.info("{any}", .{jws});

                    jwt.validateTrustChain(jws.payload.trust_chain.?, std.time.timestamp(), a) catch |e| {
                        std.log.warn("trust chain validation failed for {s} ({any})", .{ IdP, e });
                        continue;
                    };

                    // cross validate
                    jwt.crossValidateTrustChains(jws.payload.trust_chain.?, trust_chain, a) catch |e| {
                        std.log.warn("cross validation failed for {s} ({any})", .{ IdP, e });
                        continue;
                    };

                    try valid_idps.append(try a.dupe(u8, IdP));
                }

                // Return selected IdP
                if (valid_idps.items.len == 0) return null;

                // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                // User Dialog (5)
                //
                // To proceed with the A-WAYF process, user consent must be
                // obtained through a mediation dialog.
                // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

                try stdout.writeAll("Available identity providers:\n");
                for (valid_idps.items, 0..) |item, i| {
                    try std.fmt.format(stdout.writer(), "    [{d}] {s}\n", .{ i, item });
                }

                try std.fmt.format(stdout.writer(), "Please select an identity provider for authentication [0-{d}]: ", .{valid_idps.items.len - 1});
                const answer = (try nextLine(stdin.reader(), &in_buffer)).?;
                const n = std.fmt.parseInt(usize, answer, 0) catch {
                    std.log.err("not a number", .{});
                    return null;
                };
                if (n >= valid_idps.items.len) {
                    std.log.err("{d} not in 0 - {d}", .{ n, valid_idps.items.len - 1 });
                    return null;
                }

                // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                // WAYF Response (6)
                // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

                return try a.dupe(u8, valid_idps.items[n]);
            } else {
                std.log.err("unsupported federation protocol {s}", .{fed_protocol});
                return null;
            }
        }
    };
};

fn resolveTrustChain(node: []const u8, a: std.mem.Allocator) !jwt.JWS {
    if (std.mem.eql(u8, node, "http://op.a-wayf.local:8002/oidc/op")) {
        return try jwt.JWS.fromSlice(idp_token, a);
    } else {
        return error.NotFound;
    }
}

fn resolveTrustChain2(node: []const u8, a: std.mem.Allocator) !jwt.JWS {
    // +++++++++++++++++++++++++++++++++++++++++++
    // Fetch jwt containing the authority
    // +++++++++++++++++++++++++++++++++++++++++++
    var well_known_url = std.ArrayList(u8).init(a);
    defer well_known_url.deinit();
    try well_known_url.appendSlice(node);
    try well_known_url.appendSlice("/.well-known/openid-federation");
    try well_known_url.append(0);

    const well_known = try execCurl(well_known_url.items, a);
    defer a.free(well_known);

    const well_known_statement = try jwt.JWS.fromSlice(well_known, a);
    defer well_known_statement.deinit(a);

    var resolve_uri = std.ArrayList(u8).init(a);
    defer resolve_uri.deinit();

    if (well_known_statement.payload.metadata) |meta| {
        if (meta.federation_entity.federation_resolve_endpoint) |endpoint| {
            try resolve_uri.appendSlice(endpoint);
            if (verbose) std.log.info("resolve endpoint = {s}", .{endpoint});
        } else {
            return error.MissingResolveEndpoint;
        }

        if (meta.federation_entity.organization_name) |name| {
            if (verbose) std.log.info("name = {s}", .{name});
        }
    } else {
        return error.MissingMetadata;
    }

    try resolve_uri.appendSlice("?sub=");
    try resolve_uri.appendSlice(node);
    try resolve_uri.appendSlice("&anchor=");

    if (well_known_statement.payload.authority_hints) |authorities| {
        if (authorities.len == 0) return error.NoAuthorities;
        // We just use the first authority available
        // TODO: how to handle this?
        try resolve_uri.appendSlice(authorities[0]);
    } else {
        return error.MissingAuthority;
    }

    try resolve_uri.append(0);

    if (verbose)
        std.log.info("resolve uri : {s}", .{resolve_uri.items});

    // +++++++++++++++++++++++++++++++++++++++++++
    // Fetch entity statement including trust chain
    // +++++++++++++++++++++++++++++++++++++++++++

    //const url = "http://op.a-wayf.local:8002/oidc/op/resolve?sub=http://op.a-wayf.local:8002/oidc/op&anchor=http://ta.a-wayf.local:8000";
    const token = try execCurl(resolve_uri.items, a);
    defer a.free(token);

    if (verbose)
        std.log.info("statement: {s}", .{token});

    // +++++++++++++++++++++++++++++++++++++++++++
    // Now access trust chain and return it
    // +++++++++++++++++++++++++++++++++++++++++++

    const statement = try jwt.JWS.fromSlice(token, a);
    errdefer statement.deinit(a);

    if (statement.payload.trust_chain == null) {
        return error.MissingTrustChain;
    }

    return statement;
}

fn execCurl(uri: []const u8, a: std.mem.Allocator) ![]const u8 {
    // curl easy handle init, or fail
    const handle = cURL.curl_easy_init() orelse return error.CURLHandleInitFailed;
    defer cURL.curl_easy_cleanup(handle);

    var response_buffer = std.ArrayList(u8).init(a);
    errdefer response_buffer.deinit();

    //const url = "http://0.0.0.0:8002/oidc/op/resolve?sub=http://0.0.0.0:8002/oidc/op&anchor=http://0.0.0.0:8000";
    if (verbose)
        std.log.info("requesting statement via: {s}", .{uri});

    // setup curl options
    if (cURL.curl_easy_setopt(handle, cURL.CURLOPT_URL, uri.ptr) != cURL.CURLE_OK)
        return error.CouldNotSetURL;

    // set write function callbacks
    if (cURL.curl_easy_setopt(handle, cURL.CURLOPT_WRITEFUNCTION, writeToArrayListCallback) != cURL.CURLE_OK)
        return error.CouldNotSetWriteCallback;
    if (cURL.curl_easy_setopt(handle, cURL.CURLOPT_WRITEDATA, &response_buffer) != cURL.CURLE_OK)
        return error.CouldNotSetWriteCallback;

    // perform
    if (cURL.curl_easy_perform(handle) != cURL.CURLE_OK)
        return error.FailedToPerformRequest;

    return response_buffer.toOwnedSlice();
}

fn writeToArrayListCallback(data: *anyopaque, size: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    var buffer: *std.ArrayList(u8) = @alignCast(@ptrCast(user_data));
    var typed_data: [*]u8 = @ptrCast(data);
    buffer.appendSlice(typed_data[0 .. nmemb * size]) catch return 0;
    return nmemb * size;
}

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

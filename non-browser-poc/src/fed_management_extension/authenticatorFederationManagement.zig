//! Implementation of the CTAP2 authenticatorFederationManagement command as proposed by A-WAYF.

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("keylib");

const FederationManagementRequest = @import("FederationManagementRequest.zig");
const FederationManagementResponse = @import("FederationManagementResponse.zig");

const ctap2_err_no_idps = fido.ctap.StatusCodes.ctap2_err_extension_2;
const fedId = 0x40;

/// This command allows the enumeration of identity providers (IdPs) associated with credentials.
///
/// The command is associated with the command code 0x42.
///
/// Currently there are two sub-commands:
/// * `enumerateIdPBegin`: Return the first IdP and the total number of IdPs available.
/// * `enumerateIdPsGetNextIdP`: Get the next IdP.
pub fn authenticatorFederationManagement(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.ArrayList(u8),
) fido.ctap.StatusCodes {
    var di = cbor.DataItem.new(request) catch {
        return .ctap2_err_invalid_cbor;
    };
    const fmp = cbor.parse(FederationManagementRequest, di, .{
        .allocator = auth.allocator,
    }) catch {
        std.log.err("unable to map request to `FederationManagement` data type", .{});
        return .ctap2_err_invalid_cbor;
    };
    defer fmp.deinit(auth.allocator);

    switch (fmp.subCommand) {
        .enumerateIdPBegin => {
            // Enforce user verification: A client must provide a valid pinUvAuthToken.
            if (fmp.pinUvAuthProtocol == null or fmp.pinUvAuthParam == null) {
                return .ctap2_err_missing_parameter;
            }

            if (!auth.isProtected()) {
                return .ctap2_err_pin_required;
            }

            if (!auth.token.verify_token("\x01", fmp.pinUvAuthParam.?, auth.allocator)) {
                return .ctap2_err_pin_auth_invalid;
            }

            if (auth.token.permissions & fedId == 0) {
                return .ctap2_err_pin_auth_invalid;
            }

            // First we collect all credentials available
            var credentials = std.ArrayList(fido.ctap.authenticator.Credential).fromOwnedSlice(
                auth.allocator,
                auth.loadCredentials(null) catch {
                    std.log.err("federationManagement: unable to fetch credentials", .{});
                    return ctap2_err_no_idps;
                },
            );
            defer {
                for (credentials.items) |item| {
                    item.deinit(auth.allocator);
                }
                credentials.deinit();
            }

            // Now we filter out all credentials without idpId
            var i: usize = 0;
            while (true) {
                const l = credentials.items.len;
                if (i >= l) break;

                const fedEntity = credentials.items[i].getExtensions("idpId");

                if (fedEntity == null) {
                    const item = credentials.swapRemove(i);
                    item.deinit(auth.allocator);
                    continue;
                }

                i += 1;
            }

            // If there are no credentials left, we return an error.
            if (credentials.items.len == 0) {
                return ctap2_err_no_idps;
            }

            var totalIdps: usize = 1;

            // If there exists more than one IdP, we have to keep an internal state.
            if (credentials.items.len > 1) {
                // We create a list for all remaining IdPs...
                var idps = std.ArrayList([]const u8).init(auth.allocator);
                defer idps.deinit();

                // ...and then fill that list.
                blk: for (credentials.items[1..]) |cred| {
                    for (idps.items) |idp| {
                        // Every IdP MUST occur only once.
                        if (std.mem.eql(u8, idp, cred.getExtensions("idpId").?)) {
                            continue :blk;
                        }
                    }

                    // It's ok not to dupe the slice because we will
                    // serialize it during the next step.
                    idps.append(cred.getExtensions("idpId").?) catch {
                        std.log.err("federationManagement: out of memory", .{});
                        return fido.ctap.StatusCodes.ctap1_err_other;
                    };
                }

                totalIdps += idps.items.len;

                // The remaining IdPs are serialized to CBOR and stored by the authenticator.
                // How a specific authenticator keeps state is up to the developer.
                var list = std.ArrayList(u8).init(auth.allocator);
                cbor.stringify(idps.items, .{ .allocator = auth.allocator }, list.writer()) catch {
                    std.log.err("federationManagement: cbor encoding error", .{});
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
                auth.data_set = .{
                    .command = 0x42,
                    .start = auth.milliTimestamp(),
                    .key = "federationId",
                    .value = list.toOwnedSlice() catch {
                        std.log.err("federationManagement: unable to persist idp slice", .{});
                        return fido.ctap.StatusCodes.ctap1_err_other;
                    },
                };
            }

            // We create a response that contains the first
            // IdP and the number of available IdPs.
            var rv = FederationManagementResponse{
                .idpId = credentials.items[0].getExtensions("idpId").?,
                .totalIdps = @intCast(totalIdps),
            };

            // Finally, we write the response back.
            cbor.stringify(rv, .{ .allocator = auth.allocator }, out.writer()) catch {
                std.log.err("federationManagement: cbor encoding error", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
        },
        .enumerateIdPsGetNextIdP => {
            // We check if we have previously persisted IdP data.
            if (auth.data_set) |*data| {
                // First, we have to deserialize the remaining IdPs.
                const data_item = cbor.DataItem.new(data.value) catch {
                    return .ctap1_err_other;
                };
                const idPs = cbor.parse([][]const u8, data_item, .{ .allocator = auth.allocator }) catch {
                    return .ctap1_err_other;
                };
                var idps = std.ArrayList([]const u8).fromOwnedSlice(auth.allocator, idPs);
                defer idps.deinit();

                // We then get the next IdP.
                if (idps.popOrNull()) |idp| {
                    // This time our response only contains the IdP.
                    var rv = FederationManagementResponse{
                        .idpId = idp,
                    };

                    cbor.stringify(rv, .{ .allocator = auth.allocator }, out.writer()) catch {
                        std.log.err("federationManagement: cbor encoding error", .{});
                        return fido.ctap.StatusCodes.ctap1_err_other;
                    };

                    if (idps.items.len == 0) {
                        auth.allocator.free(data.value);
                        auth.data_set = null;
                    } else {
                        // Again, we persist the remaining IdPs.
                        var list = std.ArrayList(u8).init(auth.allocator);
                        cbor.stringify(idps.items, .{ .allocator = auth.allocator }, list.writer()) catch {
                            std.log.err("federationManagement: cbor encoding error", .{});
                            list.deinit();
                            return fido.ctap.StatusCodes.ctap1_err_other;
                        };
                        auth.allocator.free(data.value);
                        data.value = list.toOwnedSlice() catch {
                            std.log.err("federationManagement: unable to persist idp slice", .{});
                            auth.data_set = null;
                            return fido.ctap.StatusCodes.ctap1_err_other;
                        };
                    }
                } else {
                    auth.allocator.free(data.value);
                    auth.data_set = null;
                    return ctap2_err_no_idps;
                }
            } else {
                return ctap2_err_no_idps;
            }
        },
    }

    return fido.ctap.StatusCodes.ctap1_err_success;
}

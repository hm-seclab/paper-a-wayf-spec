const std = @import("std");
const cbor = @import("zbor");
const fido = @import("keylib");

const FederationManagementRequest = @import("FederationManagementRequest.zig");
const FederationManagementResponse = @import("FederationManagementResponse.zig");

const ctap2_err_no_idps = fido.ctap.StatusCodes.ctap2_err_extension_2;

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
            var uv: bool = true; // TODO: this should default to false
            // TODO: optionally validate pinUvAuthParam

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

            // Now we filter out all credentials without fedEntity
            var i: usize = 0;
            while (true) {
                const l = credentials.items.len;
                if (i >= l) break;

                const fedEntity = credentials.items[i].getExtensions("fedEntity");

                if (fedEntity == null) {
                    const item = credentials.swapRemove(i);
                    item.deinit(auth.allocator);
                    continue;
                }

                // We also filter out credentials if their policy
                // would be violated otherwise.
                const policy_ = fido.ctap.extensions.CredentialCreationPolicy.fromString(credentials.items[i].getExtensions("credProtect"));
                const policy = if (policy_) |policy| policy else fido.ctap.extensions.CredentialCreationPolicy.userVerificationOptional;
                if (policy != .userVerificationOptional and !uv) {
                    const item = credentials.swapRemove(i);
                    item.deinit(auth.allocator);
                    continue;
                }

                i += 1;
            }

            if (credentials.items.len == 0) {
                return ctap2_err_no_idps;
            }

            var rv = FederationManagementResponse{
                .idp = credentials.items[0].getExtensions("fedEntity").?,
                .totalIdps = @intCast(credentials.items.len),
            };

            if (credentials.items.len > 1) {
                var idps = std.ArrayList([]const u8).init(auth.allocator);
                defer idps.deinit();

                for (credentials.items[1..]) |cred| {
                    // It's ok not to dupe the slice because we will
                    // serialize it during the next step.
                    idps.append(cred.getExtensions("fedEntity").?) catch {
                        std.log.err("federationManagement: out of memory", .{});
                        return fido.ctap.StatusCodes.ctap1_err_other;
                    };
                }

                var list = std.ArrayList(u8).init(auth.allocator);
                cbor.stringify(idps, .{ .allocator = auth.allocator }, list.writer()) catch {
                    std.log.err("federationManagement: cbor encoding error", .{});
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
                auth.data_set = .{
                    .command = 0x42,
                    .start = auth.milliTimestamp(),
                    .key = "fedEntity",
                    .value = list.toOwnedSlice() catch {
                        std.log.err("federationManagement: unable to persist idp slice", .{});
                        return fido.ctap.StatusCodes.ctap1_err_other;
                    },
                };
            }

            cbor.stringify(rv, .{ .allocator = auth.allocator }, out.writer()) catch {
                std.log.err("federationManagement: cbor encoding error", .{});
                return fido.ctap.StatusCodes.ctap1_err_other;
            };
        },
        .enumerateIdPsGetNextIdP => {
            return ctap2_err_no_idps;
        },
    }

    // Locate all credentials that are eligible for retrieval.
    //var credentials = std.ArrayList(fido.ctap.authenticator.Credential).fromOwnedSlice(

    return fido.ctap.StatusCodes.ctap1_err_success;
}
const std = @import("std");
const keylib = @import("keylib");
const cbor = @import("zbor");
const uhid = @import("uhid");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    // a static credential to work with
    try data_set.append(.{
        .id = "\xb4\x40\xa4\xed\x80\x92\xe6\x9b\x19\x25\x2d\x25\x84\xc2\xa4\xce\x56\x38\x66\xd6\x4d\xb3\x13\x4e\x48\xd6\x1b\xc2\xb9\x32\xae\x23",
        .rp = "trust-anchor.testbed.oidcfed.incubator.geant.org",
        .data = "A96269645820B440A4ED8092E69B19252D2584C2A4CE563866D64DB3134E48D61BC2B932AE236475736572A26269644C0C430EFFFF5F5F5F44454D4F646E616D6565657277696E627270A1626964783074727573742D616E63686F722E746573746265642E6F6964636665642E696E63756261746F722E6765616E742E6F72676A7369676E5F636F756E740063616C676545733235366B707269766174655F6B657958201BA2453ED863B547C93AE1B2244459F2E403FC8E951B15F458335DFB3C80397467637265617465641B0000018D75C3FDC86C646973636F76657261626C65F56A657874656E73696F6E7382A26565787449644B6372656450726F746563746865787456616C7565581875736572566572696669636174696F6E4F7074696F6E616CA26565787449644569647049646865787456616C7565584168747470733A2F2F74727573742D616E63686F722E746573746265642E6F6964636665642E696E63756261746F722E6765616E742E6F72672F6F6964632F6F702F",
    });
    try data_set.append(.{
        .id = "\xa4\x40\xa4\xed\x80\x92\xe6\x9b\x19\x25\x2d\x25\x84\xc2\xa4\xce\x56\x38\x66\xd6\x4d\xb3\x13\x4e\x48\xd6\x1b\xc2\xb9\x32\xae\x23",
        .rp = "http://op.a-wayf.local:8002/oidc/op",
        .data = "A96269645820A440A4ED8092E69B19252D2584C2A4CE563866D64DB3134E48D61BC2B932AE236475736572A26269644C0C430EFFFF6F5F5F44454D4F646E616D65656461766964627270A16269646B68732D61616C656E2E64656A7369676E5F636F756E740063616C676545733235366B707269766174655F6B657958201BA2453ED863B547C93AE1B2244459F2E403FC8E951B15F458335DFB3C80397467637265617465641B0000018D75C3FDC86C646973636F76657261626C65F56A657874656E73696F6E7382A26565787449644B6372656450726F746563746865787456616C7565581875736572566572696669636174696F6E4F7074696F6E616CA26565787449644569647049646865787456616C75655823687474703A2F2F6F702E612D776179662E6C6F63616C3A383030322F6F6964632F6F70",
    });
    try data_set.append(.{
        .id = "\xa4\x40\xa4\xed\x80\x92\xe6\x9b\x19\x25\x2d\x25\x84\xc2\xa4\xce\x56\x38\x66\xd6\x4d\xb3\x13\x4e\x48\xd6\x1b\xc2\xb9\x66\xae\x23",
        .rp = "hs-aalen.de",
        .data = "A96269645820A440A4ED8092E69B19252D2584C2A4CE563866D64DB3134E48D61BC2B966AE236475736572A26269644C0C430EFF5F6F5F5F44454D4F646E616D6566706965727265627270A16269646B68732D61616C656E2E64656A7369676E5F636F756E740063616C676545733235366B707269766174655F6B657958201BA2453ED863B547C93AE1B2244459F2E403FC8E951B15F458335DFB3C80397467637265617465641B0000018D75C3FDC86C646973636F76657261626C65F56A657874656E73696F6E7382A26565787449644B6372656450726F746563746865787456616C7565581875736572566572696669636174696F6E4F7074696F6E616CA26565787449644569647049646865787456616C75654F73736F2E68732D61616C656E2E6465",
    });

    var auth = keylib.ctap.authenticator.Auth{
        .callbacks = callbacks,
        .commands = &.{
            .{ .cmd = 0x01, .cb = authenticatorMakeCredential },
            .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
            .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
            .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
            .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
            .{ .cmd = 0x42, .cb = authenticatorFederationManagement },
        },
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .extensions = &.{ "credProtect", "federationId" },
            .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
            .options = .{
                .credMgmt = false,
                .rk = true,
                .uv = true,
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // We don't support client pin
                .clientPin = null,
                .pinUvAuthToken = true,
                .alwaysUv = false,
            },
            .pinUvAuthProtocols = &.{.V2},
            .transports = &.{.usb},
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
            .remainingDiscoverableCredentials = 100,
        },
        .token = keylib.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
        .algorithms = &.{
            keylib.ctap.crypto.algorithms.Es256,
        },
        .allocator = allocator,
        .milliTimestamp = std.time.milliTimestamp,
        .random = std.crypto.random,
        .constSignCount = true,
    };
    try auth.init();

    var ctaphid = keylib.ctap.transports.ctaphid.authenticator.CtapHid.init(allocator, std.crypto.random);
    defer ctaphid.deinit();

    var u = try uhid.Uhid.open();
    defer u.close();

    while (true) {
        var buffer: [64]u8 = .{0} ** 64;
        if (u.read(&buffer)) |packet| {
            var response = ctaphid.handle(packet);
            if (response) |*res| blk: {
                switch (res.cmd) {
                    .cbor => {
                        var out: [7609]u8 = undefined;
                        const r = auth.handle(&out, res.getData());
                        std.mem.copy(u8, res._data[0..r.len], r);
                        res.len = r.len;
                    },
                    else => {},
                }

                var iter = res.iterator();
                while (iter.next()) |p| {
                    u.write(p) catch {
                        break :blk;
                    };
                }
            }
        }
        std.time.sleep(10000000);
    }
}

// /////////////////////////////////////////
// fedManagement extension
// /////////////////////////////////////////

const authenticatorFederationManagement = @import("fed_management_extension/authenticatorFederationManagement.zig").authenticatorFederationManagement;
const authenticatorMakeCredential = @import("make_credential/AuthenticatorMakeCredential.zig").authenticatorMakeCredential;

// /////////////////////////////////////////
// Data
// /////////////////////////////////////////

const Data = struct {
    rp: []const u8,
    id: []const u8,
    data: []const u8,
};

var data_set = std.ArrayList(Data).init(allocator);

// /////////////////////////////////////////
// Auth
// /////////////////////////////////////////

const UpResult = keylib.ctap.authenticator.callbacks.UpResult;
const UvResult = keylib.ctap.authenticator.callbacks.UvResult;
const Error = keylib.ctap.authenticator.callbacks.Error;

pub fn my_uv(
    /// Information about the context (e.g., make credential)
    info: [*c]const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: [*c]const u8,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: [*c]const u8,
) callconv(.C) UvResult {
    _ = info;
    _ = user;
    _ = rp;
    // The authenticator backend is only started if a correct password has been provided
    // so we return Accepted. As this state may last for multiple minutes it's important
    // that we ask for user presence, i.e. we DONT return AcceptedWithUp!
    //
    // TODO: "logout after being inactive for m minutes"
    return UvResult.Accepted;
}

pub fn my_up(
    /// Information about the context (e.g., make credential)
    info: [*c]const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: [*c]const u8,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: [*c]const u8,
) callconv(.C) UpResult {
    _ = info;
    _ = user;
    _ = rp;

    return UpResult.Accepted;
}

pub fn my_select(
    rpId: [*c]const u8,
    users: [*c][*c]const u8,
) callconv(.C) i32 {
    _ = rpId;
    _ = users;

    return 0;
}

pub fn my_read(
    id: [*c]const u8,
    rp: [*c]const u8,
    out: *[*c][*c]u8,
) callconv(.C) Error {
    var entries = std.ArrayList([*c]u8).init(allocator);

    if (id != null) {
        // get the one with the id
        const id_ = id[0..strlen(id)];

        for (data_set.items) |*entry| {
            if (std.mem.eql(u8, entry.id, id_)) {
                const d = allocator.dupeZ(u8, entry.data) catch {
                    entries.deinit();
                    return Error.OutOfMemory;
                };

                entries.append(d) catch unreachable;
                entries.append(null) catch unreachable;
                const o = entries.toOwnedSlice() catch unreachable;
                out.* = o.ptr;
                return Error.SUCCESS;
            }
        }

        entries.deinit();
        return Error.DoesNotExist;
    } else if (rp != null) {
        // get all associated with id
        const rp_ = rp[0..strlen(rp)];

        for (data_set.items) |*entry| {
            if (std.mem.eql(u8, entry.rp, rp_)) {
                const d = allocator.dupeZ(u8, entry.data) catch {
                    entries.deinit();
                    return Error.OutOfMemory;
                };

                entries.append(d) catch unreachable;
            }
        }

        if (entries.items.len > 0) {
            entries.append(null) catch unreachable;
            const o = entries.toOwnedSlice() catch unreachable;
            out.* = o.ptr;
            return Error.SUCCESS;
        }

        entries.deinit();
        return Error.DoesNotExist;
    } else {
        // get all
        for (data_set.items) |*entry| {
            if (!std.mem.eql(u8, entry.rp, "Root")) {
                const d = allocator.dupeZ(u8, entry.data) catch {
                    entries.deinit();
                    return Error.OutOfMemory;
                };

                entries.append(d) catch unreachable;
            }
        }

        if (entries.items.len > 0) {
            entries.append(null) catch unreachable;
            const o = entries.toOwnedSlice() catch unreachable;
            out.* = o.ptr;
            return Error.SUCCESS;
        }

        entries.deinit();
        return Error.DoesNotExist;
    }

    return Error.DoesNotExist;
}

pub fn my_write(
    id: [*c]const u8,
    rp: [*c]const u8,
    data: [*c]const u8,
) callconv(.C) Error {
    if (id == null or rp == null or data == null) {
        return Error.Other;
    }

    const id_ = id[0..strlen(id)];
    const rp_ = rp[0..strlen(rp)];
    const data_ = data[0..strlen(data)];

    for (data_set.items) |*entry| {
        if (std.mem.eql(u8, entry.id, id_)) {
            allocator.free(entry.data);
            entry.data = allocator.dupe(u8, data_) catch {
                // TODO: here we should actually free the entry as the data is invalid
                return Error.OutOfMemory;
            };
            return Error.SUCCESS;
        }
    }

    const id2 = allocator.dupe(u8, id_) catch {
        return Error.OutOfMemory;
    };
    const rp2 = allocator.dupe(u8, rp_) catch {
        allocator.free(id2);
        return Error.OutOfMemory;
    };
    const data2 = allocator.dupe(u8, data_) catch {
        allocator.free(id2);
        allocator.free(rp2);
        return Error.OutOfMemory;
    };

    data_set.append(Data{
        .rp = rp2,
        .id = id2,
        .data = data2,
    }) catch {
        allocator.free(id2);
        allocator.free(rp2);
        allocator.free(data2);
        return Error.OutOfMemory;
    };

    return Error.SUCCESS;
}

pub fn my_delete(
    id: [*c]const u8,
) callconv(.C) Error {
    _ = id;
    return Error.Other;
}

const callbacks = keylib.ctap.authenticator.callbacks.Callbacks{
    .up = my_up,
    .uv = my_uv,
    .select = my_select,
    .read = my_read,
    .write = my_write,
    .delete = my_delete,
};

// MISC

pub fn strlen(s: [*c]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    return i;
}

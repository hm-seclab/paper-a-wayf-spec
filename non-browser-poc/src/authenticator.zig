const std = @import("std");
const keylib = @import("keylib");
const cbor = @import("zbor");
const uhid = @import("uhid");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    var auth = keylib.ctap.authenticator.Auth{
        .callbacks = callbacks,
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .extensions = &.{ .credProtect, .fedEntity },
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
    } else if (rp == null) {
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

            if (entries.items.len > 0) {
                entries.append(null) catch unreachable;
                const o = entries.toOwnedSlice() catch unreachable;
                out.* = o.ptr;
                return Error.SUCCESS;
            }
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

            if (entries.items.len > 0) {
                entries.append(null) catch unreachable;
                const o = entries.toOwnedSlice() catch unreachable;
                out.* = o.ptr;
                return Error.SUCCESS;
            }
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

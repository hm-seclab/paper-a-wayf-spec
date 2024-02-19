const std = @import("std");

const client = @import("keylib").client;
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const client_pin = client.cbor_commands.client_pin;
const cred_management = client.cbor_commands.cred_management;
const Info = client.cbor_commands.Info;
const Transport = client.Transports.Transport;

const stdin = std.io.getStdIn();
const stdout = std.io.getStdOut();

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main() !void {
    var input = try std.process.argsWithAllocator(allocator);
    input.deinit();

    _ = input.skip();
    const cmd = input.next();

    if (cmd == null) {
        try help(stdout.writer());
        std.os.exit(1);
    }

    if (std.mem.eql(u8, "-L", cmd.?)) {
        try listDevices(stdout.writer());
    } else if (std.mem.eql(u8, "-h", cmd.?)) {
        try help(stdout.writer());
    } else if (std.mem.eql(u8, "-I", cmd.?)) {
        const path = input.next();
        if (path == null) {
            std.log.err("missing path", .{});
            try help(stdout.writer());
            std.os.exit(1);
        }

        var dev = try getDevice(path.?);
        if (dev == null) {
            std.log.err("unable to open device", .{});
            std.os.exit(1);
        }
        defer dev.?.deinit();

        try getInfo(stdout.writer(), &dev.?);
    }
}

fn help(writer: anytype) !void {
    try writer.writeAll(
        \\keylib - command line tool
        \\---------------------------------
        \\
        \\About: TBD
        \\
        \\Commands:
        \\       h, help: Print this help text
        \\
        \\       -L: List all available authenticators
        \\       -I <path>: Get information about a selected device
    );
}

fn listDevices(writer: anytype) !void {
    // Get all devices connect to the platform
    const transports = try client.Transports.enumerate(allocator, .{});
    defer transports.deinit();

    for (transports.devices, 0..) |*device, i| {
        if (i > 0) try writer.writeByte('\n');
        var str = try device.allocPrint(allocator);
        defer allocator.free(str);
        try writer.print("{d}) {s}", .{ i, str });
    }
}

fn getDevice(path: []const u8) !?Transport {
    const transports = try client.Transports.enumerate(allocator, .{});

    const i = blk: for (transports.devices, 0..) |*device, i| {
        var str = try device.allocPrint(allocator);
        defer allocator.free(str);

        if (std.mem.indexOfAny(u8, path, str)) |_| {
            break :blk i;
        }
    } else {
        transports.deinit();
        return null;
    };

    const t = transports.devices[i];
    var j: usize = 0;
    while (j < transports.devices.len) : (j += 1) {
        if (j != i) {
            transports.devices[j].deinit();
        }
    }
    transports.allocator.free(transports.devices);
    return t;
}

//fn select_device(writer: anytype, in: []const u8) !void {
//    if (State.transports == null) {
//        State.transports = try client.Transports.enumerate(allocator, .{});
//    }
//
//    if (State.transports.?.devices.len == 0) {
//        try writer.writeAll("no device available");
//    }
//
//    var items = std.mem.split(u8, in, " ");
//    _ = items.next();
//    if (items.next()) |item| {
//        const n = std.fmt.parseInt(usize, item, 0) catch {
//            try writer.print("{s} is not a number", .{item});
//            return;
//        };
//
//        if (n >= State.transports.?.devices.len) {
//            try writer.print("please provide a number between {d} and {d}", .{ 0, State.transports.?.devices.len - 1 });
//            return;
//        }
//
//        if (State.device) |dev| dev.close();
//
//        State.device = &State.transports.?.devices[n];
//        State.device.?.open() catch {
//            try writer.print("unable to open device {d}", .{n});
//            return;
//        };
//        State.n = n;
//    } else {
//        try writer.print("please provide a number between {d} and {d}", .{ 0, State.transports.?.devices.len - 1 });
//    }
//}

fn getInfo(writer: anytype, device: *client.Transports.Transport) !void {
    const infos = try (try authenticatorGetInfo(device)).@"await"(allocator);
    defer infos.deinit(allocator);
    const info = try infos.deserializeCbor(Info, allocator);
    defer info.deinit(allocator);

    try std.json.stringify(info, .{ .whitespace = .indent_2, .emit_null_optional_fields = false }, writer);
}

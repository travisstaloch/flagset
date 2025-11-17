const std = @import("std");

const flagset = @import("flagset");

pub fn main() !void {
    const flags = [_]flagset.Flag{
        .init(bool, "flag", .{ .short = 'f', .desc = "flag description" }),
        .init(u32, "count", .{ .desc = "count description" }),
        .init(enum { one, two }, "enum", .{ .kind = .positional, .desc = "enum description" }),
        // NOTE: `default_value_ptr=&null` means there is no default value.  so we have to give it a type.
        .init(?[]const u8, "opt-string", .{ .short = 's', .desc = "opt-string description", .default_value_ptr = &@as(?[]const u8, "opt-string-default") }),
        .init([]const u8, "string", .{ .desc = "string description" }),
        .init([]const u8, "pos-str", .{ .kind = .positional, .desc = "pos-str description" }),
        .init(u8, "with-default", .{ .desc = "with-default description", .default_value_ptr = &@as(u8, 10) }),
        .init([]const u8, "list", .{ .desc = "list description", .kind = .list, .short = 'l' }),
    };

    const alloc = std.heap.page_allocator; // TODO use a better allocator
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var result = flagset.parseFromIter(&flags, args, .{ .allocator = alloc }) catch |e| switch (e) {
        error.HelpRequested => {
            std.debug.print("{f}", .{flagset.fmtUsage(&flags, ": <45", .full,
                \\
                \\usage: demo <options>
                \\
                \\
            )});
            return;
        },
        else => return e,
    };
    std.debug.print("parsed: {f}\n", .{flagset.fmtParsed(&flags, result.parsed, .{})});
    std.debug.print("unparsed args: ", .{});
    while (result.unparsed_args.next()) |arg| std.debug.print("{s} ", .{arg});
    std.debug.print("\n", .{});
}

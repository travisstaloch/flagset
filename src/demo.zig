const std = @import("std");
const flagset = @import("flagset");

pub fn main() !void {
    const flags = [_]flagset.Flag{
        .init(bool, "flag", .{ .desc = "flag help", .short = 'f' }),
        .init(u32, "count", .{ .desc = "count help" }),
        .init(enum { one, two }, "enum", .{ .desc = "enum help", .kind = .positional }),
        .init(?[]const u8, "opt-string", .{ .desc = "opt-string help", .short = 's' }),
        .init([]const u8, "string", .{ .desc = "string help" }),
        .init([]const u8, "pos-str", .{ .desc = "pos-str help", .kind = .positional }),
    };

    const result = flagset.parseFromIter(&flags, std.process.args(), .{}) catch |e| switch (e) {
        error.HelpRequested => {
            std.debug.print("{: <45}", .{flagset.fmtUsage(&flags, .full,
                \\
                \\usage: demo <options>
                \\
                \\
            )});
            return;
        },
        else => return e,
    };
    std.debug.print("parsed: {}\n", .{flagset.fmtParsed(&flags, &result.parsed, .{})});
}

const std = @import("std");
const testing = std.testing;

const flagset = @import("flagset");

const exepath = "exepath";
inline fn testArgs(comptime rest: []const [:0]const u8) []const [:0]const u8 {
    return comptime &[_][:0]const u8{exepath} ++ rest;
}

fn expectParsed(
    comptime flags: []const flagset.Flag,
    args: []const [:0]const u8,
    expected: flagset.Parsed(flags),
) !void {
    const result = try flagset.parseFromSlice(flags, args, .{});
    try testing.expectEqual(expected, result.parsed);
    try testing.expectEqual(0, result.unparsed_args.len);
}

const bool_flag = [_]flagset.Flag{.init(bool, "bool", .{})};

test "Parsed" {
    const Parsed = flagset.Parsed(&bool_flag);
    const fields = @typeInfo(Parsed).@"struct".fields;
    try testing.expectEqual(bool, fields[0].type);
    try testing.expectEqual("bool", fields[0].name);
    try testing.expectEqual(null, fields[0].defaultValue());
}

test "default values" {
    try expectParsed(
        &[_]flagset.Flag{.init(bool, "bool", .{ .default_value_ptr = &true })},
        testArgs(&.{}),
        .{ .bool = true },
    );
    try expectParsed(
        &[_]flagset.Flag{.init(u8, "u8", .{ .default_value_ptr = &@as(u8, 10) })},
        testArgs(&.{}),
        .{ .u8 = 10 },
    );
    try expectParsed(
        &[_]flagset.Flag{.init(?u8, "u8", .{ .default_value_ptr = &@as(?u8, null) })},
        testArgs(&.{}),
        .{ .u8 = null },
    );
}

test "accept std.process.args()/argsAlloc() mem.tokenize()/split()" {
    var iter = try std.process.argsWithAllocator(std.testing.allocator);
    defer iter.deinit();
    _ = try flagset.parseFromIter(&[_]flagset.Flag{}, iter, .{});

    const args = try std.process.argsAlloc(std.testing.allocator);
    defer std.process.argsFree(std.testing.allocator, args);
    _ = try flagset.parseFromSlice(&[_]flagset.Flag{}, args, .{});

    _ = try flagset.parseFromIter(&[_]flagset.Flag{}, std.mem.tokenizeScalar(u8, exepath, ' '), .{});
    _ = try flagset.parseFromIter(&[_]flagset.Flag{}, std.mem.splitScalar(u8, exepath, ' '), .{});
}

test "parsing stops before first non-flag arg or after '--'" {
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "--bool", "true", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "--bool", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "--bool", "true", "-", "foo" }), .{});
        try testing.expectEqual(2, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "--bool", "true", "--", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "--bool", "--", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
}

test "parse bool" {
    try expectParsed(&bool_flag, testArgs(&.{"--bool"}), .{ .bool = true });
    try expectParsed(&bool_flag, testArgs(&.{"--no-bool"}), .{ .bool = false });
    try expectParsed(&bool_flag, testArgs(&.{"--bool=true"}), .{ .bool = true });
    try expectParsed(&bool_flag, testArgs(&.{"--bool=false"}), .{ .bool = false });
    try expectParsed(&bool_flag, testArgs(&.{ "--bool", "false" }), .{ .bool = false });
    try expectParsed(&bool_flag, testArgs(&.{ "--bool", "true" }), .{ .bool = true });

    // non flag
    const result = try flagset.parseFromSlice(
        &.{.init(bool, "bool", .{ .default_value_ptr = &true })},
        testArgs(&.{"--no-bool=true"}),
        .{},
    );
    try testing.expectEqual(1, result.unparsed_args.len);

    // don't match flag names without two leading dashes
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{"bool"}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{"-bool"}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{"no-bool"}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{"-no-bool"}), .{}),
    );
}

test "parse int" {
    const int_flag = [_]flagset.Flag{.init(i8, "int", .{})};
    try expectParsed(&int_flag, testArgs(&.{"--int=10"}), .{ .int = 10 });
    try expectParsed(&int_flag, testArgs(&.{"--int=-10"}), .{ .int = -10 });
    try expectParsed(&int_flag, testArgs(&.{ "--int", "10" }), .{ .int = 10 });
    try expectParsed(&int_flag, testArgs(&.{ "--int", "10" }), .{ .int = 10 });
    // bases
    try expectParsed(&int_flag, testArgs(&.{"--int=0x10"}), .{ .int = 0x10 });
    try expectParsed(&int_flag, testArgs(&.{"--int=0b10"}), .{ .int = 0b10 });
    try expectParsed(&int_flag, testArgs(&.{ "--int", "0o10" }), .{ .int = 0o10 });
}

test "parse float" {
    const float_flag = [_]flagset.Flag{.init(f32, "float", .{})};
    try expectParsed(&float_flag, testArgs(&.{"--float=10.0"}), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{"--float=10.0"}), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{ "--float", "10.0" }), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{ "--float", "10.0" }), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{ "--float", "2718e28" }), .{ .float = 2718e28 });
}

test "parse enum" {
    const enum_flag = [_]flagset.Flag{.init(enum { foo, bar }, "enum", .{})};
    try expectParsed(&enum_flag, testArgs(&.{"--enum=foo"}), .{ .@"enum" = .foo });
    try expectParsed(&enum_flag, testArgs(&.{ "--enum", "bar" }), .{ .@"enum" = .bar });
}

test "parse string" {
    const string_flag = [_]flagset.Flag{.init([]const u8, "str", .{})};
    try testing.expectEqualStrings(
        "foo",
        (try flagset.parseFromSlice(&string_flag, testArgs(&.{"--str=foo"}), .{})).parsed.str,
    );
    try testing.expectEqualStrings(
        "foo",
        (try flagset.parseFromSlice(&string_flag, testArgs(&.{"--str=foo"}), .{})).parsed.str,
    );
    try testing.expectEqualStrings(
        "\"foo bar\"",
        (try flagset.parseFromSlice(&string_flag, testArgs(&.{ "--str", "\"foo bar\"" }), .{})).parsed.str,
    );
}

test "parse optionals" {
    const opt_int_flag = [_]flagset.Flag{.init(?i8, "int", .{})};
    try expectParsed(&opt_int_flag, testArgs(&.{"--no-int"}), .{ .int = null });
    try expectParsed(&opt_int_flag, testArgs(&.{"--no-int"}), .{ .int = null });
    try expectParsed(&opt_int_flag, testArgs(&.{"--int=10"}), .{ .int = 10 });
}

test "required flags" {
    const flags = [_]flagset.Flag{
        .init(i8, "int", .{}),
        .init(bool, "bool", .{}),
    };
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, testArgs(&.{}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, testArgs(&.{"--int=0"}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, testArgs(&.{"--bool"}), .{}),
    );
}

test "duplicate flags" {
    try testing.expectError(
        error.DuplicateFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{ "--bool", "--no-bool" }), .{}),
    );
}

test "parse into ptrs" {
    {
        var int: i8 = 0;
        _ = try flagset.parseFromSlice(
            &[_]flagset.Flag{.init(i8, "int", .{})},
            testArgs(&.{"--int=10"}),
            .{ .ptrs = .{ .int = &int } },
        );
        try testing.expectEqual(10, int);
    }
    {
        var int: i8 = 0;
        _ = try flagset.parseFromSlice(
            &[_]flagset.Flag{.init(i8, "int", .{ .kind = .positional })},
            testArgs(&.{"10"}),
            .{ .ptrs = .{ .int = &int } },
        );
        try testing.expectEqual(10, int);
    }
    { // default value
        var int: i8 = 0;
        _ = try flagset.parseFromSlice(
            &[_]flagset.Flag{.init(i8, "int", .{ .default_value_ptr = &@as(i8, 10) })},
            testArgs(&.{}),
            .{ .ptrs = .{ .int = &int } },
        );
        try testing.expectEqual(10, int);
    }
}

test "positional args" {
    try expectParsed(
        &[_]flagset.Flag{.init(i8, "int", .{ .kind = .positional })},
        testArgs(&.{"10"}),
        .{ .int = 10 },
    );

    try expectParsed(&.{
        .init(i8, "int", .{ .kind = .positional }),
        .init(bool, "bool", .{ .kind = .positional }),
    }, testArgs(&.{ "10", "true" }), .{ .int = 10, .bool = true });
}

test "mixed positional args - any arg order" {
    const flags = [_]flagset.Flag{
        .init(i8, "int1", .{}),
        .init(i8, "int2", .{ .kind = .positional }),
        .init(i8, "int3", .{ .kind = .positional }),
    };
    const args = [_][]const [:0]const u8{ &.{ "--int1", "1" }, &.{"2"}, &.{"3"} };
    const P = flagset.Parsed(&flags);
    const expected = P{ .int1 = 1, .int2 = 2, .int3 = 3 };
    const expected2 = P{ .int1 = 1, .int2 = 3, .int3 = 2 };
    try expectParsed(
        &flags,
        testArgs(args[0] ++ args[1] ++ args[2]),
        expected,
    );
    try expectParsed(
        &flags,
        testArgs(args[0] ++ args[2] ++ args[1]),
        expected2,
    );
    try expectParsed(
        &flags,
        testArgs(args[1] ++ args[0] ++ args[2]),
        expected,
    );
    try expectParsed(
        &flags,
        testArgs(args[1] ++ args[2] ++ args[0]),
        expected,
    );
    try expectParsed(
        &flags,
        testArgs(args[2] ++ args[0] ++ args[1]),
        expected2,
    );
    try expectParsed(
        &flags,
        testArgs(args[2] ++ args[1] ++ args[0]),
        expected2,
    );
}

test "command composition" {
    const cmd_flag = [_]flagset.Flag{
        .init(enum { push, pull }, "cmd", .{ .kind = .positional }),
    };
    const result = try flagset.parseFromSlice(&cmd_flag, &.{ "git", "push", "origin", "--force" }, .{});
    try testing.expectEqual(.push, result.parsed.cmd);

    const push_flagset = [_]flagset.Flag{
        .init([]const u8, "remote", .{ .kind = .positional }),
        .init(bool, "force", .{ .default_value_ptr = &false }),
    };
    switch (result.parsed.cmd) {
        .push => {
            const pushres = try flagset.parseFromSlice(
                &push_flagset,
                result.unparsed_args,
                .{ .flags = .{ .skip_first_arg = false } },
            );
            try testing.expectEqual("origin", pushres.parsed.remote);
            try testing.expectEqual(true, pushres.parsed.force);
        },
        .pull => {
            unreachable;
        },
    }
}

test "short names" {
    const flags = [_]flagset.Flag{
        .init([]const u8, "host", .{ .kind = .positional }),
        .init(u16, "port", .{ .short = 'p' }),
        .init(?u16, "format", .{ .short = 'f', .default_value_ptr = &@as(?u16, null) }),
    };
    try expectParsed(
        &flags,
        &.{ "ssh", "server.com", "--port", "2222" },
        .{ .host = "server.com", .port = 2222, .format = null },
    );
    try expectParsed(
        &flags,
        &.{ "ssh", "server.com", "-p", "2222" },
        .{ .host = "server.com", .port = 2222, .format = null },
    );
    try expectParsed(
        &flags,
        &.{ "ssh", "server.com", "-p=2222" },
        .{ .host = "server.com", .port = 2222, .format = null },
    );
    try expectParsed(
        &flags,
        &.{ "ssh", "server.com", "-p", "2222", "-f", "42" },
        .{ .host = "server.com", .port = 2222, .format = 42 },
    );

    // should fail to recognize shorts with double dash and stop parsing
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, &.{ "ssh", "server.com", "--p", "2222" }, .{}),
    );
    const result = try flagset.parseFromSlice(
        &.{.init(u8, "int", .{ .short = 'i', .default_value_ptr = &@as(u8, 0) })},
        testArgs(&.{ "--i", "2222" }),
        .{},
    );
    try testing.expectEqual(0, result.parsed.int);
    try testing.expectEqual(2, result.unparsed_args.len);
}

test "one letter non-short name" {
    const flags = [_]flagset.Flag{.init(u16, "p", .{})};
    try expectParsed(&flags, testArgs(&.{ "--p", "2222" }), .{ .p = 2222 });
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, &.{ "-p", "2222" }, .{}),
    );
}

test "codepoint" {
    const flags = [_]flagset.Flag{.init(u32, "codepoint", .{ .int_from_utf8 = true, .kind = .positional })};
    try expectParsed(&flags, testArgs(&.{"a"}), .{ .codepoint = 'a' });
    try expectParsed(&flags, testArgs(&.{"👏"}), .{ .codepoint = '👏' });
}

test "parseFn" {
    const flags = [_]flagset.Flag{
        .init(std.net.Address, "ip", .{
            .parseFn = flagset.checkParseFn(std.net.Address, &struct {
                fn parseFn(
                    value_str: []const u8,
                    args_iter_ptr: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!std.net.Address {
                    const to_parse = if (value_str.len != 0)
                        value_str
                    else if (args_iter_ptr.next()) |next_arg|
                        next_arg
                    else
                        return error.UnexpectedValue;
                    return std.net.Address.parseIp(to_parse, 0) catch
                        return error.UnexpectedValue;
                }
            }.parseFn),
        }),
    };
    const ip = "127.0.0.1";
    const result = try flagset.parseFromSlice(&flags, testArgs(&.{ "--ip", ip }), .{});
    const expected = std.net.Address.parseIp(ip, 0) catch unreachable;
    try testing.expect(expected.eql(result.parsed.ip));

    // positional
    const result2 = try flagset.parseFromSlice(&[_]flagset.Flag{
        .init(std.net.Address, "ip", .{
            .kind = .positional,
            .parseFn = flagset.checkParseFn(std.net.Address, &struct {
                fn parseFn(
                    value_str: []const u8,
                    _: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!std.net.Address {
                    return std.net.Address.parseIp(value_str, 0) catch
                        return error.UnexpectedValue;
                }
            }.parseFn),
        }),
    }, testArgs(&.{ip}), .{});
    try testing.expect(expected.eql(result2.parsed.ip));
}

test "parseFn misc" {
    // parse into ptr
    const I = i64;
    var time: I = undefined;
    const result = try flagset.parseFromSlice(&[_]flagset.Flag{
        .init(I, "time", .{
            .kind = .positional,
            .parseFn = flagset.checkParseFn(I, &struct {
                fn parseFn(
                    _: []const u8,
                    _: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!i64 {
                    return 42;
                }
            }.parseFn),
        }),
    }, testArgs(&.{"42s"}), .{ .ptrs = .{ .time = &time } });

    try testing.expectEqual(42, time);
    try testing.expect(result.parsed.time != 42); // should be undefined

    // stop parsing
    const result2 = try flagset.parseFromSlice(&[_]flagset.Flag{
        .init(I, "time", .{
            .parseFn = flagset.checkParseFn(I, &struct {
                fn parseFn(
                    _: []const u8,
                    _: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!i64 {
                    return error.NonFlagArgument;
                }
            }.parseFn),
            .default_value_ptr = &@as(I, 0),
        }),
    }, testArgs(&.{ "--foo", "42" }), .{});
    try testing.expectEqual(2, result2.unparsed_args.len);
}

const fmt_flagset = [_]flagset.Flag{
    .init(bool, "flag", .{ .desc = "flag help", .short = 'f' }),
    .init(u32, "count", .{ .desc = "count help" }),
    .init(enum { one, two }, "enum", .{ .desc = "enum help", .kind = .positional }),
    .init(?[]const u8, "opt-string", .{ .desc = "opt-string help", .short = 's' }),
    .init([]const u8, "string", .{ .desc = "string help" }),
    .init([]const u8, "pos-str", .{ .desc = "pos-str help", .kind = .positional }),
    .init([]const u8, "list", .{ .desc = "list help", .kind = .list }),
};

test "fmtUsage" {
    try testing.expectFmt(
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\
    , "{f}", .{flagset.fmtUsage(&fmt_flagset, ": <25", .brief,
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\
    )});

    try testing.expectFmt(
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\options:
        \\  --help, -h             show this message and exit
        \\  --flag, --no-flag, -f  flag help
        \\  --count <u32>          count help
        \\  <enum:one|two>         enum help
        \\  --opt-string, --no-opt-string, -s <string>
        \\                         opt-string help
        \\  --string <string>      string help
        \\  <pos-str:string>       pos-str help
        \\  --list <string> (many) list help
        \\
        \\
    , "{f}", .{flagset.fmtUsage(&fmt_flagset, ": <25", .full,
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\
    )});

    try testing.expectFmt(
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\options:
        \\  --help, -h                                 show this message and exit
        \\  --flag, --no-flag, -f                      flag help
        \\  --count <u32>                              count help
        \\  <enum:one|two>                             enum help
        \\  --opt-string, --no-opt-string, -s <string> opt-string help
        \\  --string <string>                          string help
        \\  <pos-str:string>                           pos-str help
        \\  --list <string> (many)                     list help
        \\
        \\
    , "{f}", .{flagset.fmtUsage(&fmt_flagset, ": <45", .full,
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\
    )});
}

test "fmtParsed - round trip" {
    var count: u32 = undefined;
    var result = try flagset.parseFromSlice(
        &fmt_flagset,
        testArgs(&.{ "--flag", "--count", "10", "two", "--no-opt-string", "--string", "s", "pos-str", "--list", "foo", "--list", "bar" }),
        .{ .ptrs = .{ .count = &count }, .allocator = testing.allocator },
    );
    defer result.deinit(testing.allocator);

    try testing.expectFmt(
        \\--flag --count 10 two --no-opt-string --string s pos-str --list foo --list bar
    ,
        "{f}",
        .{flagset.fmtParsed(&fmt_flagset, result.parsed, .{ .ptrs = .{ .count = &count } })},
    );

    try testing.expectFmt(
        \\--flag --count 10 enum:two --no-opt-string --string s pos-str:pos-str --list foo --list bar
    ,
        "{f}",
        .{flagset.fmtParsed(&fmt_flagset, result.parsed, .{
            .flags = .{ .show_positional_names = true },
            .ptrs = .{ .count = &count },
        })},
    );

    var buf: [128]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "exepath {f}", .{flagset.fmtParsed(&fmt_flagset, result.parsed, .{})});
    {
        var r = try flagset.parseFromIter(&fmt_flagset, std.mem.tokenizeScalar(u8, formatted, ' '), .{ .allocator = testing.allocator });
        defer r.deinit(testing.allocator);
        try testing.expectEqual(result.parsed.flag, r.parsed.flag);
        try testing.expectEqual(result.parsed.count, r.parsed.count);
        try testing.expectEqual(result.parsed.@"enum", r.parsed.@"enum");
        try testing.expect(result.parsed.@"opt-string" == null);
        try testing.expect(r.parsed.@"opt-string" == null);
        try testing.expectEqualStrings(result.parsed.string, r.parsed.string);
        try testing.expectEqualStrings(result.parsed.@"pos-str", r.parsed.@"pos-str");
        try testing.expectEqual(2, r.parsed.list.items.len);
        try testing.expectEqualStrings("foo", r.parsed.list.items[0]);
        try testing.expectEqualStrings("bar", r.parsed.list.items[1]);
    }
    {
        var r = try flagset.parseFromIter(&fmt_flagset, std.mem.splitScalar(u8, formatted, ' '), .{ .allocator = testing.allocator });
        defer r.deinit(testing.allocator);
        try testing.expectEqual(result.parsed.flag, r.parsed.flag);
        try testing.expectEqual(result.parsed.count, r.parsed.count);
        try testing.expectEqual(result.parsed.@"enum", r.parsed.@"enum");
        try testing.expect(result.parsed.@"opt-string" == null);
        try testing.expect(r.parsed.@"opt-string" == null);
        try testing.expectEqualStrings(result.parsed.string, r.parsed.string);
        try testing.expectEqualStrings(result.parsed.@"pos-str", r.parsed.@"pos-str");
        try testing.expectEqual(2, r.parsed.list.items.len);
        try testing.expectEqualStrings("foo", r.parsed.list.items[0]);
        try testing.expectEqualStrings("bar", r.parsed.list.items[1]);
    }
}

test "StaticBitsetMap" {
    _ = flagset.StaticBitsetMap(std.math.maxInt(u16), u8).initEmpty(undefined);
    _ = flagset.StaticBitsetMap(0, u8).initEmpty(undefined);
    { // getIndex
        var shorts = flagset.StaticBitsetMap(256, u8).initEmpty(undefined);
        for (0..256) |i| {
            shorts.bitset |= @as(u256, 1) << @as(u8, @intCast(i));
            for (0..i + 1) |j| {
                try testing.expectEqual(j, shorts.getIndex(@intCast(j)).?);
            }
        }
    }

    {
        var buf: [20]u8 = undefined;
        var shorts = flagset.StaticBitsetMap(20, u8).initEmpty(&buf);
        shorts.set(0, 0);
        try testing.expectEqual(0, shorts.get(0));
        try testing.expectEqual(0, shorts.getIndex(0));
        try testing.expectEqual(1, shorts.count());
        shorts.set(0, 1);
        try testing.expectEqual(1, shorts.get(0));
        try testing.expectEqual(0, shorts.getIndex(0));
        try testing.expectEqual(1, shorts.count());
        shorts.set(19, 4);
        try testing.expectEqual(4, shorts.get(19));
        try testing.expectEqual(0, shorts.getIndex(0));
        try testing.expectEqual(1, shorts.getIndex(19));
        try testing.expectEqual(2, shorts.count());
        shorts.set(10, 3);
        try testing.expectEqual(3, shorts.get(10));
        try testing.expectEqual(0, shorts.getIndex(0));
        try testing.expectEqual(1, shorts.getIndex(10));
        try testing.expectEqual(2, shorts.getIndex(19));
        try testing.expectEqual(3, shorts.count());
        shorts.set(5, 2);
        try testing.expectEqual(2, shorts.get(5));
        try testing.expectEqual(0, shorts.getIndex(0));
        try testing.expectEqual(1, shorts.getIndex(5));
        try testing.expectEqual(2, shorts.getIndex(10));
        try testing.expectEqual(3, shorts.getIndex(19));
        try testing.expectEqual(4, shorts.count());

        try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, shorts.values[0..shorts.count()]);
    }

    const testFn = struct {
        fn testFn(buf: []u8, keys_len: u8, random: std.Random) !void {
            const alloc = std.testing.allocator;
            const keys = buf[0..keys_len];
            random.shuffle(u8, keys);
            const values = try alloc.alloc(u8, keys_len);
            defer alloc.free(values);
            var actual = flagset.StaticBitsetMap(256, u8).initEmpty(values);
            for (0..keys_len) |i| {
                actual.set(keys[i], @intCast(i));
            }

            for (0..keys_len) |i| {
                try testing.expectEqual(@as(u8, @intCast(i)), actual.get(keys[i]));
            }
        }
    }.testFn;

    // fuzz
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();
    var buf: [256]u8 = undefined;
    for (0..buf.len) |i| buf[i] = @intCast(i);
    try testFn(&buf, 255, random);
    for (0..100) |_| {
        const keys_len = random.int(u8);
        try testFn(&buf, keys_len, random);
    }
}

test "combined shorts" {
    const flags = [_]flagset.Flag{
        .init(bool, "fa", .{ .short = 'a' }),
        .init(bool, "fb", .{ .short = 'b' }),
        .init(bool, "fc", .{ .short = 'c', .default_value_ptr = &false }),
    };
    try expectParsed(&flags, testArgs(&.{"-abc"}), .{ .fa = true, .fb = true, .fc = true });
    try expectParsed(&flags, testArgs(&.{"-ab"}), .{ .fa = true, .fb = true, .fc = false });
    try expectParsed(&flags, testArgs(&.{ "-c", "-ab" }), .{ .fa = true, .fb = true, .fc = true });

    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, testArgs(&.{"-ac"}), .{}),
    );
}

test "list" {
    const flags = [_]flagset.Flag{
        .init([]const u8, "list", .{ .kind = .list, .short = 'l' }),
    };
    {
        const result = try flagset.parseFromSlice(&flags, testArgs(&.{}), .{});
        try testing.expectEqual(0, result.parsed.list.items.len);
    }
    {
        var result = try flagset.parseFromSlice(&flags, testArgs(&.{ "--list", "foo", "--list", "bar" }), .{ .allocator = testing.allocator });
        defer result.deinit(testing.allocator);
        try testing.expectEqual(2, result.parsed.list.items.len);
        try testing.expectEqualStrings("foo", result.parsed.list.items[0]);
        try testing.expectEqualStrings("bar", result.parsed.list.items[1]);
    }
    {
        var result = try flagset.parseFromSlice(&flags, testArgs(&.{ "-l", "foo", "-l", "bar" }), .{ .allocator = testing.allocator });
        defer result.deinit(testing.allocator);
        try testing.expectEqual(2, result.parsed.list.items.len);
        try testing.expectEqualStrings("foo", result.parsed.list.items[0]);
        try testing.expectEqualStrings("bar", result.parsed.list.items[1]);
    }
    {
        var result = try flagset.parseFromSlice(&flags, testArgs(&.{ "-l=foo", "-l=bar" }), .{ .allocator = testing.allocator });
        defer result.deinit(testing.allocator);
        try testing.expectEqual(2, result.parsed.list.items.len);
        try testing.expectEqualStrings("foo", result.parsed.list.items[0]);
        try testing.expectEqualStrings("bar", result.parsed.list.items[1]);
    }
}

test "list parse into ptrs" {
    var list: std.ArrayListUnmanaged([]const u8) = .{};
    defer list.deinit(std.testing.allocator);
    const flags = [_]flagset.Flag{
        .init([]const u8, "list", .{ .kind = .list }),
    };
    _ = try flagset.parseFromSlice(
        &flags,
        testArgs(&.{ "--list", "foo", "--list", "bar" }),
        .{ .allocator = testing.allocator, .ptrs = .{ .list = &list } },
    );
    try testing.expectEqualSlices([]const u8, &.{ "foo", "bar" }, list.items);
}

test "memory safety" {
    try std.testing.checkAllAllocationFailures(testing.allocator, struct {
        fn testFn(alloc: std.mem.Allocator) !void {
            const flags = [_]flagset.Flag{
                .init(i8, "l1", .{ .kind = .list }),
                .init(bool, "l2", .{ .kind = .list }),
            };
            var result = try flagset.parseFromSlice(
                &flags,
                testArgs(&.{ "--l1", "10", "--l2", "true", "--l1", "20", "-l2", "false" }),
                .{ .allocator = alloc },
            );
            defer result.deinit(alloc);
        }
    }.testFn, .{});
}

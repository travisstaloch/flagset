const std = @import("std");
const flagset = @import("flagset");
const testing = std.testing;

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
    try testing.expectEqual(null, fields[0].default_value);
}

test "default values" {
    try expectParsed(
        &[_]flagset.Flag{.init(bool, "bool", .{ .default_value = &true })},
        testArgs(&.{}),
        .{ .bool = true },
    );
    try expectParsed(
        &[_]flagset.Flag{.init(u8, "u8", .{ .default_value = &@as(u8, 10) })},
        testArgs(&.{}),
        .{ .u8 = 10 },
    );
    try expectParsed(
        &[_]flagset.Flag{.init(?u8, "u8", .{ .default_value = &@as(?u8, null) })},
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
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "-bool", "true", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "-bool", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "-bool", "true", "-", "foo" }), .{});
        try testing.expectEqual(2, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "-bool", "true", "--", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
    {
        const result = try flagset.parseFromSlice(&bool_flag, testArgs(&.{ "-bool", "--", "foo" }), .{});
        try testing.expectEqual(1, result.unparsed_args.len);
    }
}

test "parse bool" {
    try expectParsed(&bool_flag, testArgs(&.{"-bool"}), .{ .bool = true });
    try expectParsed(&bool_flag, testArgs(&.{"--bool"}), .{ .bool = true });
    try expectParsed(&bool_flag, testArgs(&.{"-no-bool"}), .{ .bool = false });
    try expectParsed(&bool_flag, testArgs(&.{"-bool=true"}), .{ .bool = true });
    try expectParsed(&bool_flag, testArgs(&.{"-bool=false"}), .{ .bool = false });
    try expectParsed(&bool_flag, testArgs(&.{ "-bool", "false" }), .{ .bool = false });
    try expectParsed(&bool_flag, testArgs(&.{ "-bool", "true" }), .{ .bool = true });

    // non flag
    const result = try flagset.parseFromSlice(
        &.{.init(bool, "bool", .{ .default_value = &true })},
        testArgs(&.{"-no-bool=true"}),
        .{},
    );
    try testing.expectEqual(1, result.unparsed_args.len);

    // don't match flag names without a leading dash
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{"bool"}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{"no-bool"}), .{}),
    );
}

test "parse int" {
    const int_flag = [_]flagset.Flag{.init(i8, "int", .{})};
    try expectParsed(&int_flag, testArgs(&.{"-int=10"}), .{ .int = 10 });
    try expectParsed(&int_flag, testArgs(&.{"--int=-10"}), .{ .int = -10 });
    try expectParsed(&int_flag, testArgs(&.{ "-int", "10" }), .{ .int = 10 });
    try expectParsed(&int_flag, testArgs(&.{ "--int", "10" }), .{ .int = 10 });
    // bases
    try expectParsed(&int_flag, testArgs(&.{"-int=0x10"}), .{ .int = 0x10 });
    try expectParsed(&int_flag, testArgs(&.{"--int=0b10"}), .{ .int = 0b10 });
    try expectParsed(&int_flag, testArgs(&.{ "--int", "0o10" }), .{ .int = 0o10 });
}

test "parse float" {
    const float_flag = [_]flagset.Flag{.init(f32, "float", .{})};
    try expectParsed(&float_flag, testArgs(&.{"-float=10.0"}), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{"--float=10.0"}), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{ "-float", "10.0" }), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{ "--float", "10.0" }), .{ .float = 10.0 });
    try expectParsed(&float_flag, testArgs(&.{ "--float", "2718e28" }), .{ .float = 2718e28 });
}

test "parse enum" {
    const enum_flag = [_]flagset.Flag{.init(enum { foo, bar }, "enum", .{})};
    try expectParsed(&enum_flag, testArgs(&.{"-enum=foo"}), .{ .@"enum" = .foo });
    try expectParsed(&enum_flag, testArgs(&.{ "-enum", "bar" }), .{ .@"enum" = .bar });
}

test "parse string" {
    const string_flag = [_]flagset.Flag{.init([]const u8, "str", .{})};
    try testing.expectEqualStrings(
        "foo",
        (try flagset.parseFromSlice(&string_flag, testArgs(&.{"-str=foo"}), .{})).parsed.str,
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
    try expectParsed(&opt_int_flag, testArgs(&.{"-no-int"}), .{ .int = null });
    try expectParsed(&opt_int_flag, testArgs(&.{"--no-int"}), .{ .int = null });
    try expectParsed(&opt_int_flag, testArgs(&.{"-int=10"}), .{ .int = 10 });
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
        flagset.parseFromSlice(&flags, testArgs(&.{"-int=0"}), .{}),
    );
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, testArgs(&.{"-bool"}), .{}),
    );
}

test "duplicate flags" {
    try testing.expectError(
        error.DuplicateFlag,
        flagset.parseFromSlice(&bool_flag, testArgs(&.{ "-bool", "--no-bool" }), .{}),
    );
}

test "parse into ptrs" {
    {
        var int: i8 = undefined;
        const result = try flagset.parseFromSlice(
            &[_]flagset.Flag{.init(i8, "int", .{})},
            testArgs(&.{"-int=10"}),
            .{ .ptrs = .{ .int = &int } },
        );
        try testing.expect(result.parsed.int != 10); // should be undefined
        try testing.expectEqual(10, int);
    }
    {
        var int: i8 = undefined;
        const result = try flagset.parseFromSlice(
            &[_]flagset.Flag{.init(i8, "int", .{ .kind = .positional })},
            testArgs(&.{"10"}),
            .{ .ptrs = .{ .int = &int } },
        );
        try testing.expect(result.parsed.int != 10); // should be undefined
        try testing.expectEqual(10, int);
    }
    { // default value
        var int: i8 = undefined;
        const result = try flagset.parseFromSlice(
            &[_]flagset.Flag{.init(i8, "int", .{ .default_value = &@as(i8, 10) })},
            testArgs(&.{}),
            .{ .ptrs = .{ .int = &int } },
        );
        try testing.expect(result.parsed.int != 10); // should be undefined
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
    const args = [_][]const [:0]const u8{ &.{ "-int1", "1" }, &.{"2"}, &.{"3"} };
    const expected = .{ .int1 = 1, .int2 = 2, .int3 = 3 };
    const expected2 = .{ .int1 = 1, .int2 = 3, .int3 = 2 };
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

test "mixed positional args - any flag order" {
    const flags = comptime [_]flagset.Flag{
        .init(i8, "int1", .{}),
        .init(i8, "int2", .{ .kind = .positional }),
        .init(i8, "int3", .{ .kind = .positional }),
    };
    const args = [_][:0]const u8{ "-int1", "1", "2", "3" };
    const expected = .{ .int1 = 1, .int2 = 2, .int3 = 3 };
    const expected2 = .{ .int1 = 1, .int2 = 3, .int3 = 2 };

    try expectParsed(
        &(.{flags[0]} ++ .{flags[1]} ++ .{flags[2]}),
        testArgs(&args),
        expected,
    );
    try expectParsed(
        &(.{flags[0]} ++ .{flags[2]} ++ .{flags[1]}),
        testArgs(&args),
        expected2,
    );
    try expectParsed(
        &(.{flags[1]} ++ .{flags[0]} ++ .{flags[2]}),
        testArgs(&args),
        expected,
    );
    try expectParsed(
        &(.{flags[1]} ++ .{flags[2]} ++ .{flags[0]}),
        testArgs(&args),
        expected,
    );
    try expectParsed(
        &(.{flags[2]} ++ .{flags[0]} ++ .{flags[1]}),
        testArgs(&args),
        expected2,
    );
    try expectParsed(
        &(.{flags[2]} ++ .{flags[1]} ++ .{flags[0]}),
        testArgs(&args),
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
        .init(bool, "force", .{ .default_value = &false }),
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
    };
    const result2 = try flagset.parseFromSlice(&flags, &.{ "ssh", "server.com", "--port", "2222" }, .{});
    try testing.expectEqualStrings("server.com", result2.parsed.host);
    try testing.expectEqual(2222, result2.parsed.port);

    const result = try flagset.parseFromSlice(&flags, &.{ "ssh", "server.com", "-p", "2222" }, .{});
    try testing.expectEqualStrings("server.com", result.parsed.host);
    try testing.expectEqual(2222, result.parsed.port);

    // should fail to recognize shorts with double dash and stop parsing
    try testing.expectError(
        error.MissingRequiredFlag,
        flagset.parseFromSlice(&flags, &.{ "ssh", "server.com", "--p", "2222" }, .{}),
    );
    const result3 = try flagset.parseFromSlice(
        &.{.init(u8, "int", .{ .short = 'i', .default_value = &@as(u8, 0) })},
        testArgs(&.{ "--i", "2222" }),
        .{},
    );
    try testing.expectEqual(0, result3.parsed.int);
    try testing.expectEqual(2, result3.unparsed_args.len);
}

test "one letter non-short name" {
    try expectParsed(&.{.init(u16, "p", .{})}, testArgs(&.{ "-p", "2222" }), .{ .p = 2222 });
    try expectParsed(&.{.init(u16, "p", .{})}, testArgs(&.{ "--p", "2222" }), .{ .p = 2222 });
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
                    result_ptr: *std.net.Address,
                    value_str: []const u8,
                    args_iter_ptr: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!void {
                    const to_parse = if (value_str.len != 0)
                        value_str
                    else if (args_iter_ptr.next()) |next_arg|
                        next_arg
                    else
                        return error.UnexpectedValue;
                    result_ptr.* = std.net.Address.parseIp(to_parse, 0) catch
                        return error.UnexpectedValue;
                }
            }.parseFn),
        }),
    };
    const ip = "127.0.0.1";
    const result = try flagset.parseFromSlice(&flags, testArgs(&.{ "-ip", ip }), .{});
    const expected = std.net.Address.parseIp(ip, 0) catch unreachable;
    try testing.expect(expected.eql(result.parsed.ip));

    // positional
    const result2 = try flagset.parseFromSlice(&[_]flagset.Flag{
        .init(std.net.Address, "ip", .{
            .kind = .positional,
            .parseFn = flagset.checkParseFn(std.net.Address, &struct {
                fn parseFn(
                    result_ptr: *std.net.Address,
                    value_str: []const u8,
                    _: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!void {
                    result_ptr.* = std.net.Address.parseIp(value_str, 0) catch
                        return error.UnexpectedValue;
                }
            }.parseFn),
        }),
    }, testArgs(&.{ip}), .{});
    try testing.expect(expected.eql(result2.parsed.ip));
}

test "parseFn misc" {
    // parse into ptr
    const T = i64;
    var time: T = undefined;
    const result = try flagset.parseFromSlice(&[_]flagset.Flag{
        .init(T, "time", .{
            .kind = .positional,
            .parseFn = flagset.checkParseFn(T, &struct {
                fn parseFn(
                    result_ptr: *T,
                    _: []const u8,
                    _: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!void {
                    result_ptr.* = 42;
                }
            }.parseFn),
        }),
    }, testArgs(&.{"42s"}), .{ .ptrs = .{ .time = &time } });

    try testing.expectEqual(42, time);
    try testing.expect(result.parsed.time != 42); // should be undefined

    // stop parsing
    const result2 = try flagset.parseFromSlice(&[_]flagset.Flag{
        .init(T, "time", .{
            .parseFn = flagset.checkParseFn(T, &struct {
                fn parseFn(
                    _: *T,
                    _: []const u8,
                    _: anytype,
                    _: flagset.ParsedValueFlags,
                ) flagset.ParseError!void {
                    return error.NonFlagArgument;
                }
            }.parseFn),
            .default_value = &@as(T, 0),
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
};

test "fmtUsage" {
    try testing.expectFmt(
        \\
        \\usage: exepath <options>
        \\
        \\help message
        \\
        \\
    , "{: <25}", .{flagset.fmtUsage(&fmt_flagset, .brief,
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
        \\
        \\
    , "{: <25}", .{flagset.fmtUsage(&fmt_flagset, .full,
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
        \\
        \\
    , "{: <45}", .{flagset.fmtUsage(&fmt_flagset, .full,
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
    const result = try flagset.parseFromSlice(
        &fmt_flagset,
        testArgs(&.{ "--flag", "--count", "10", "two", "--no-opt-string", "--string", "\"s\"", "pos-str" }),
        .{ .ptrs = .{ .count = &count } },
    );

    try testing.expectFmt(
        \\--flag --count 10 two --no-opt-string --string "s" pos-str
    ,
        "{}",
        .{flagset.fmtParsed(&fmt_flagset, result.parsed, .{ .ptrs = .{ .count = &count } })},
    );

    try testing.expectFmt(
        \\--flag --count 10 enum:two --no-opt-string --string "s" pos-str:pos-str
    ,
        "{}",
        .{flagset.fmtParsed(&fmt_flagset, result.parsed, .{
            .flags = .{ .show_positional_names = true },
            .ptrs = .{ .count = &count },
        })},
    );

    var buf: [128]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "exepath {}", .{flagset.fmtParsed(&fmt_flagset, result.parsed, .{})});

    const result2 = try flagset.parseFromIter(&fmt_flagset, std.mem.tokenizeScalar(u8, formatted, ' '), .{});
    try testing.expectEqual(result.parsed.flag, result2.parsed.flag);
    try testing.expectEqual(result.parsed.count, result2.parsed.count);
    try testing.expectEqual(result.parsed.@"enum", result2.parsed.@"enum");
    try testing.expect(result.parsed.@"opt-string" == null);
    try testing.expect(result2.parsed.@"opt-string" == null);
    try testing.expectEqualStrings(result.parsed.string, result2.parsed.string);
    try testing.expectEqualStrings(result.parsed.@"pos-str", result2.parsed.@"pos-str");

    const result3 = try flagset.parseFromIter(&fmt_flagset, std.mem.splitScalar(u8, formatted, ' '), .{});
    try testing.expectEqual(result.parsed.flag, result3.parsed.flag);
    try testing.expectEqual(result.parsed.count, result3.parsed.count);
    try testing.expectEqual(result.parsed.@"enum", result3.parsed.@"enum");
    try testing.expect(result.parsed.@"opt-string" == null);
    try testing.expect(result3.parsed.@"opt-string" == null);
    try testing.expectEqualStrings(result.parsed.string, result3.parsed.string);
    try testing.expectEqualStrings(result.parsed.@"pos-str", result3.parsed.@"pos-str");
}

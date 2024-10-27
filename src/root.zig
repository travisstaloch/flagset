//!
//! this lib uses many ideas from https://github.com/Games-by-Mason/structopt
//!

/// A single command line flag.  This struct allows users to describe their cli.
/// Names must be distinct.
pub const Flag = struct {
    type: type,
    name: [:0]const u8,
    options: Options,

    pub fn init(typ: type, name: [:0]const u8, options: Options) Flag {
        return .{ .type = typ, .name = name, .options = options };
    }

    pub fn parseFn(comptime flag: Flag) ?*const ParseFn(flag.type) {
        return if (flag.options.parseFn) |f| @alignCast(@ptrCast(f)) else null;
    }

    pub const Options = struct {
        /// usage description which appears after flag name and type
        desc: ?[]const u8 = null,
        /// short name. i.e. 'b'
        short: ?u8 = null,
        /// default value.  when provided this flag is optional.
        default_value: ?*const anyopaque = null,
        /// positional flags don't require a name and will be parsed in
        /// declared order.
        kind: enum { positional, named } = .named,
        /// allow an integer flag to be parsed from a utf8 string such as 'a' or '👏'
        int_from_utf8: bool = false,
        /// a custom parse function.  because this is type erased, you should
        /// pass `checkParseFn(myParseFn)` to verify its signature.
        parseFn: ?*const anyopaque = null,
    };

    fn fmtFlagType(flag: Flag, cw: anytype, comptime T: type) !void {
        if (flag.options.kind == .named)
            try cw.writeAll(" <")
        else
            try cw.writeAll(":");
        try cw.writeAll(if (comptime isZigString(T)) "string" else @typeName(T));
        if (flag.options.kind == .named) try cw.writeByte('>');
    }

    pub fn format(
        flag: Flag,
        comptime _: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var cw_state = std.io.countingWriter(writer);
        const cw = cw_state.writer();
        try cw.writeAll("  ");

        if (flag.options.kind == .positional) {
            try cw.writeByte('<');
        } else {
            try cw.writeAll("--");
        }
        try cw.writeAll(flag.name);

        if (flag.options.kind == .named) {
            switch (@typeInfo(flag.type)) {
                .bool, .optional => {
                    try cw.writeAll(", --no-");
                    try cw.writeAll(flag.name);
                },
                else => {},
            }
            if (flag.options.short) |s| {
                try cw.writeAll(", -");
                _ = try cw.writeByte(s);
            }
        }

        switch (@typeInfo(flag.type)) {
            .bool => {},
            .@"enum" => |info| {
                try cw.writeAll(":");
                inline for (info.fields, 0..) |f, i| {
                    if (i != 0) try cw.writeByte('|');
                    try cw.writeAll(f.name);
                }
            },
            .optional => |info| {
                try fmtFlagType(flag, cw, info.child);
            },
            else => {
                try fmtFlagType(flag, cw, flag.type);
            },
        }

        if (flag.options.kind == .positional) try cw.writeByte('>');

        if (flag.options.desc) |desc| {
            const width = options.width orelse 25;
            if (cw_state.bytes_written > width) {
                try writer.writeByte('\n');
                try writer.writeByteNTimes(@intCast(options.fill), width);
                try writer.writeAll(desc);
            } else {
                try writer.writeByteNTimes(@intCast(options.fill), width - cw_state.bytes_written);
                try writer.writeAll(desc);
            }
        }
    }
};

pub fn ParseFn(comptime T: type) type {
    return fn (
        ptr: *T,
        value_str: []const u8,
        iter_ptr: anytype,
        parsed_flags: ParsedValueFlags,
    ) Error!void;
}

/// used to verify the signature of a parseFn
pub inline fn checkParseFn(comptime T: type, comptime parseFn: anytype) *const anyopaque {
    comptime {
        const ParseFnT = @TypeOf(parseFn);
        if (ParseFnT != *const ParseFn(T))
            @compileError("unexpected parseFn type:\n" ++ @typeName(ParseFnT) ++ "\nexpected:\n" ++ @typeName(ParseFn(T)));
        return @ptrCast(parseFn);
    }
}

/// a struct with field names and types from 'flags'
pub inline fn Parsed(comptime flags: []const Flag) type {
    comptime {
        var fields: []const std.builtin.Type.StructField = &.{};
        for (flags, 0..) |flag, i| {
            // check for duplicate names
            for (fields, 0..) |f, j| {
                if (mem.eql(u8, flag.name, f.name)) duplicateNameError(flag, i, j);
            }
            if (mem.indexOfScalar(u8, flag.name, ' ') != null)
                invalidNameError(flag, i, "spaces in name");
            // TODO when flag.int_from_utf8, check type info is .int
            fields = fields ++ .{.{
                .type = flag.type,
                .name = flag.name,
                .default_value = null,
                .is_comptime = false,
                .alignment = 0,
            }};
        }
        return @Type(.{ .@"struct" = .{
            .layout = .auto,
            .decls = &.{},
            .is_tuple = false,
            .fields = fields,
        } });
    }
}

/// a struct similar to Parsed() where each field is a `?*T = null` instead of T
pub fn ParsedPtrs(
    comptime flags: []const Flag,
    comptime mutability: enum { @"const", mut },
) type {
    comptime {
        var fields: []const std.builtin.Type.StructField = &.{};
        for (flags, 0..) |flag, i| {
            // check for duplicate names
            for (fields, 0..) |f, j| {
                if (mem.eql(u8, flag.name, f.name)) duplicateNameError(flag, i, j);
            }
            if (mem.indexOfScalar(u8, flag.name, ' ') != null)
                invalidNameError(flag, i, "spaces in name");
            const T = ?if (mutability == .@"const") *const flag.type else *flag.type;
            const default: T = null;
            const default_ptr: ?*const anyopaque = @ptrCast(&default);
            fields = fields ++ .{.{
                .type = T,
                .name = flag.name,
                .default_value = default_ptr,
                .is_comptime = false,
                .alignment = 0,
            }};
        }
        return @Type(.{ .@"struct" = .{
            .layout = .auto,
            .decls = &.{},
            .is_tuple = false,
            .fields = fields,
        } });
    }
}

pub fn ParseResult(comptime flags: []const Flag, comptime RestArgs: type) type {
    return struct {
        parsed: Parsed(flags),
        /// remaing, unparsed args
        unparsed_args: RestArgs,
    };
}

pub const Iter = struct {
    slice: []const []const u8,

    pub fn init(slice: []const []const u8) Iter {
        return .{ .slice = slice };
    }

    pub fn next(iter: *Iter) ?[]const u8 {
        if (iter.slice.len == 0) return null;
        defer iter.slice = iter.slice[1..];
        return iter.slice[0];
    }
};

pub fn iterPeek(iter_ptr: anytype) ?[]const u8 {
    var iter = iter_ptr.*;
    return iter.next();
}

pub const Error = error{
    NonFlagArgument,
    ParseFailure,
    DuplicateFlag,
    MissingRequiredFlag,
    HelpRequested,
} ||
    std.fmt.ParseIntError;

pub fn ParseOptions(comptime flags: []const Flag) type {
    return struct {
        flags: Flags = .{},
        ptrs: ParsedPtrs(flags, .mut) = .{},
        const Flags = packed struct(u8) {
            skip_first_arg: bool = true,
            _padding: u7 = undefined,
        };
    };
}

pub fn parseFromSlice(
    comptime flags: []const Flag,
    args: []const []const u8,
    parse_options: ParseOptions(flags),
) Error!ParseResult(flags, []const []const u8) {
    const result = try parseFromIter(flags, Iter.init(args), parse_options);
    return .{ .parsed = result.parsed, .unparsed_args = result.unparsed_args.slice };
}

pub fn parseFromIter(
    comptime flags: []const Flag,
    args_iter: anytype,
    parse_options: ParseOptions(flags),
) Error!ParseResult(flags, @TypeOf(args_iter)) {
    if (flags.len == 0) return .{ .parsed = undefined, .unparsed_args = args_iter };

    var args_iter_mut = args_iter;
    if (parse_options.flags.skip_first_arg) _ = args_iter_mut.next();
    const P = Parsed(flags);
    const FieldEnum = std.meta.FieldEnum(P);
    const pinfo = @typeInfo(P);
    if (@hasField(@TypeOf(args_iter), "slice"))
        debug("parseIntoPtrs({s}) field names {s}", .{ args_iter_mut.slice, std.meta.fieldNames(P) });

    var parsed: P = undefined;
    var seen_flags = std.enums.EnumSet(FieldEnum).initEmpty();
    var args_iter_prev = args_iter_mut;
    args: while (args_iter_mut.next()) |arg| : (args_iter_prev = args_iter_mut) {
        assert(arg.len > 0);
        var parsed_flags: ParsedValueFlags = .{ .negated = false, .int_from_utf8 = false };
        var is_double_dash = false;
        var starts_with_dash = false;

        // split arg into a flag name key and value.  value is anything after '='
        const key, const value = if (arg[0] == '-') kv: {
            // arg starts with at least "-"

            try checkHelp(arg);

            starts_with_dash = true;
            var arg_mut = arg[1..];
            if (arg_mut.len > 0 and arg_mut[0] == '-') {
                // arg starts with "--"
                is_double_dash = true;
                arg_mut = arg_mut[1..];
            }
            if (arg_mut.len == 0) {
                // '-' or '--'
                if (!is_double_dash) args_iter_mut = args_iter_prev;
                break;
            }
            if (mem.startsWith(u8, arg_mut, "no-")) {
                parsed_flags.negated = true;
                arg_mut = arg_mut[3..];
            }

            break :kv if (mem.indexOfScalar(u8, arg_mut, '=')) |eq_idx|
                .{ arg_mut[0..eq_idx], arg_mut[eq_idx + 1 ..] }
            else
                .{ arg_mut, "" };
        } else .{ arg, "" };

        debug("arg '{s}' key '{s}' value '{?s}' negated {}", .{ arg, key, value, parsed_flags.negated });

        const short_sentinel = 255;
        const shorts = comptime blk: {
            assert(pinfo.@"struct".fields.len < short_sentinel);
            var shorts = [1]u8{short_sentinel} ** 256;
            var i: u8 = 0;
            for (flags) |flag| {
                if (flag.options.short) |s| {
                    if (shorts[s] != short_sentinel)
                        invalidNameError(flag, i, "duplicate short name '" ++ [_]u8{s} ++ "' in flag");
                    shorts[s] = i;
                }
                i += 1;
            }
            break :blk shorts;
        };

        // match key
        var mfield_enum: ?FieldEnum = null;
        if (starts_with_dash) {
            // match long names first
            mfield_enum = stringToEnum(FieldEnum, key);
            if (mfield_enum == null and key.len == 1) {
                // shorts must have single dash like '-b' and not '--b'
                if (is_double_dash) {
                    args_iter_mut = args_iter_prev;
                    break;
                }
                const short = shorts[key[0]];
                if (short != short_sentinel) mfield_enum = @enumFromInt(short);
            }
        }

        if (mfield_enum) |field_enum| {
            debug("match {s}", .{arg});
            if (seen_flags.contains(field_enum)) return error.DuplicateFlag;
            switch (field_enum) {
                inline else => |inline_fe| {
                    const flag = flags[@intFromEnum(inline_fe)];
                    parsed_flags.int_from_utf8 = flag.options.int_from_utf8;

                    const name = @tagName(inline_fe);
                    const ptr = if (@field(parse_options.ptrs, name)) |ptr|
                        ptr
                    else
                        &@field(parsed, name);

                    const merr = if (comptime flag.parseFn()) |parseFn|
                        parseFn(ptr, value, &args_iter_mut, parsed_flags)
                    else
                        parseValue(ptr, value, &args_iter_mut, parsed_flags);

                    _ = merr catch |e| switch (e) {
                        error.NonFlagArgument => {
                            args_iter_mut = args_iter_prev;
                            break;
                        },
                        else => return e,
                    };

                    seen_flags.insert(field_enum);
                    continue :args;
                },
            }
        }

        // parse positionals
        var missing_flags_iter = seen_flags.complement().iterator();
        while (missing_flags_iter.next()) |missing_flag| {
            // debug("positional arg {s} missing_flag {s}", .{ arg, @tagName(missing_flag) });
            switch (missing_flag) {
                inline else => |inline_fe| {
                    const flag = flags[@intFromEnum(inline_fe)];
                    if (flag.options.kind == .positional) {
                        debug("positional match for arg '{s}'. flag '{s}'", .{ arg, @tagName(missing_flag) });
                        parsed_flags.int_from_utf8 = flag.options.int_from_utf8;

                        const name = @tagName(inline_fe);
                        const ptr = if (@field(parse_options.ptrs, name)) |ptr|
                            ptr
                        else
                            &@field(parsed, name);

                        const merr = if (comptime flag.parseFn()) |parseFn|
                            parseFn(ptr, arg, &args_iter_mut, parsed_flags)
                        else
                            parseValue(ptr, arg, &args_iter_mut, parsed_flags);

                        _ = merr catch |e| switch (e) {
                            error.NonFlagArgument => {
                                args_iter_mut = args_iter_prev;
                                break;
                            },
                            else => return e,
                        };

                        seen_flags.insert(missing_flag);
                        continue :args;
                    }
                },
            }
        }

        args_iter_mut = args_iter_prev;
        break;
    }

    // assign default values to missing flags
    var missing_flags_iter = seen_flags.complement().iterator();
    while (missing_flags_iter.next()) |missing_flag| {
        switch (missing_flag) {
            inline else => |inline_fe| {
                const flag = flags[@intFromEnum(inline_fe)];
                if (flag.options.default_value) |default| {
                    const name = @tagName(inline_fe);
                    const ptr = if (@field(parse_options.ptrs, name)) |ptr|
                        ptr
                    else
                        &@field(parsed, name);

                    ptr.* = @as(*const flag.type, @alignCast(@ptrCast(default))).*;
                    seen_flags.insert(missing_flag);
                } else {
                    if (!@import("builtin").is_test)
                        log.warn("missing required flag: {}", .{flag});
                }
            },
        }
    }

    if (seen_flags.count() != pinfo.@"struct".fields.len) {
        return error.MissingRequiredFlag;
    }

    return .{ .parsed = parsed, .unparsed_args = args_iter_mut };
}

pub const ParsedValueFlags = packed struct(u8) {
    negated: bool,
    int_from_utf8: bool,
    _padding: u6 = undefined,
};

fn parseInt(comptime T: type, s: []const u8, parsed_flags: ParsedValueFlags) !T {
    if (parsed_flags.int_from_utf8) {
        if (std.unicode.utf8ByteSequenceLength(s[0])) |cplen| {
            if (std.unicode.utf8ValidateSlice(s[0..cplen])) blk: {
                const cp = std.unicode.utf8Decode(s[0..cplen]) catch break :blk;
                if (std.math.cast(T, cp)) |int| return int;
            }
        } else |_| {}
    }
    return std.fmt.parseInt(T, s, 0);
}

fn parseBool(arg: []const u8) ?bool {
    var buf = [1]u8{0} ** 5;
    const len = @min(arg.len, buf.len);
    @memcpy(buf[0..len], arg[0..len]);
    const n = mem.readInt(u40, &buf, .big);
    return switch (n) {
        mem.readInt(u40, "true\x00", .big),
        => true,
        mem.readInt(u40, "false", .big),
        => false,
        else => null,
    };
}

fn parseValue(
    ptr: anytype,
    value_str: []const u8,
    arg_iter_ptr: anytype,
    parsed_flags: ParsedValueFlags,
) Error!void {
    const T = @TypeOf(ptr.*);
    const info = @typeInfo(T);
    debug("parseValue({s}) value_str '{s}' negated {}", .{ @tagName(info), value_str, parsed_flags.negated });
    switch (info) {
        .bool => if (value_str.len == 0) {
            if (iterPeek(arg_iter_ptr)) |next| {
                debug("bool next '{s}'", .{next});
                if (parseBool(next)) |b| {
                    _ = arg_iter_ptr.next();
                    ptr.* = b;
                    return;
                }
            }
            ptr.* = !parsed_flags.negated;
        } else if (parsed_flags.negated)
            return error.ParseFailure
        else {
            ptr.* = if (parseBool(value_str)) |b|
                b
            else
                return error.ParseFailure;
        },

        .int => if (value_str.len > 0) {
            ptr.* = try parseInt(T, value_str, parsed_flags);
        } else if (iterPeek(arg_iter_ptr)) |next| {
            ptr.* = try parseInt(T, next, parsed_flags);
            _ = arg_iter_ptr.next();
        } else return error.ParseFailure,

        .float => if (value_str.len > 0) {
            ptr.* = try std.fmt.parseFloat(T, value_str);
        } else if (iterPeek(arg_iter_ptr)) |next| {
            ptr.* = try std.fmt.parseFloat(T, next);
            _ = arg_iter_ptr.next();
        } else return error.ParseFailure,

        .@"enum" => if (value_str.len > 0) {
            ptr.* = std.meta.stringToEnum(T, value_str) orelse
                return error.ParseFailure;
        } else if (iterPeek(arg_iter_ptr)) |next| {
            ptr.* = std.meta.stringToEnum(T, next) orelse
                return error.ParseFailure;
            _ = arg_iter_ptr.next();
        } else return error.ParseFailure,

        .pointer => if (comptime isZigString(T)) {
            if (value_str.len > 0) {
                ptr.* = value_str;
            } else if (iterPeek(arg_iter_ptr)) |next| {
                ptr.* = next;
                _ = arg_iter_ptr.next();
            } else {
                return error.ParseFailure;
            }
        } else unsupportedType(T),

        .optional => |x| if (parsed_flags.negated) {
            ptr.* = null;
        } else {
            var val: x.child = undefined;
            try parseValue(&val, value_str, arg_iter_ptr, parsed_flags);
            ptr.* = val;
        },

        else => unsupportedType(T),
    }
}

pub const UsageMode = enum { full, brief };

pub fn FmtUsage(comptime flags: []const Flag) type {
    return struct {
        usage: []const u8,
        mode: UsageMode,

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.writeAll(self.usage);

            if (self.mode == .brief) return;
            const help_flags = "  --help, -h";
            try writer.writeAll("options:\n" ++ help_flags);
            const width = options.width orelse 25;
            const help_desc = "show this message and exit\n";
            if (help_flags.len > width) {
                try writer.writeByte('\n');
                try writer.writeByteNTimes(@intCast(options.fill), width);
                try writer.writeAll(help_desc);
            } else {
                try writer.writeByteNTimes(@intCast(options.fill), width - help_flags.len);
                try writer.writeAll(help_desc);
            }

            inline for (flags) |flag| {
                try std.fmt.formatType(flag, fmt, options, writer, 0);
                try writer.writeByte('\n');
            }
            try writer.writeByte('\n');
        }
    };
}

pub fn fmtUsage(
    comptime flags: []const Flag,
    mode: UsageMode,
    usage: []const u8,
) std.fmt.Formatter(FmtUsage(flags).format) {
    return .{ .data = .{ .usage = usage, .mode = mode } };
}

pub fn ParsedFmtOptions(comptime flags: []const Flag) type {
    return struct {
        flags: Flags = .{},
        ptrs: ParsedPtrs(flags, .@"const") = .{},
        pub const Flags = packed struct(u8) {
            show_positional_names: bool = false,
            _padding: u7 = undefined,
        };
    };
}

pub fn FmtParsed(comptime flags: []const Flag) type {
    return struct {
        parsed: Parsed(flags),
        options: ParsedFmtOptions(flags),

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            inline for (flags, 0..) |flag, i| {
                if (i != 0) try writer.writeByte(' ');
                const value = if (@field(self.options.ptrs, flag.name)) |ptr|
                    ptr.*
                else
                    @field(self.parsed, flag.name);

                if (flag.options.kind == .named) {
                    try writer.writeAll("--");
                    switch (@typeInfo(@TypeOf(value))) {
                        .bool => {
                            if (!value) try writer.writeAll("no-");
                            try writer.writeAll(flag.name);
                        },
                        .optional => {
                            if (value) |v| {
                                try fmtParsedVal(v, fmt, options, writer);
                            } else {
                                try writer.writeAll("no-");
                                try writer.writeAll(flag.name);
                            }
                        },
                        else => {
                            try writer.writeAll(flag.name);
                            try writer.writeByte(' ');
                            try fmtParsedVal(value, fmt, options, writer);
                        },
                    }
                } else {
                    if (self.options.flags.show_positional_names) {
                        try writer.writeAll(flag.name);
                        try writer.writeByte(':');
                    }
                    try fmtParsedVal(value, fmt, options, writer);
                }
            }
        }
    };
}

pub fn fmtParsed(
    comptime flags: []const Flag,
    parsed: Parsed(flags),
    options: ParsedFmtOptions(flags),
) std.fmt.Formatter(FmtParsed(flags).format) {
    return .{ .data = .{ .parsed = parsed, .options = options } };
}

fn checkHelp(arg: []const u8) error{HelpRequested}!void {
    var buf = [1]u8{0} ** 6;
    const len = @min(arg.len, buf.len);
    @memcpy(buf[0..len], arg[0..len]);
    const n = mem.readInt(u48, &buf, .big);
    switch (n) {
        mem.readInt(u48, "-h\x00\x00\x00\x00", .big),
        mem.readInt(u48, "--help", .big),
        => return error.HelpRequested,
        else => {},
    }
}

fn isZigString(comptime T: type) bool {
    return comptime blk: {
        // Only pointer types can be strings, no optionals
        const info = @typeInfo(T);
        if (info != .pointer) break :blk false;
        const ptr = info.pointer;
        // Check for CV qualifiers that would prevent coerction to []const u8
        if (ptr.is_volatile or ptr.is_allowzero) break :blk false;
        // If it's already a slice, simple check.
        if (ptr.size == .Slice) break :blk ptr.child == u8;

        // Otherwise check if it's an array type that coerces to slice.
        // if (ptr.size == .One) {
        //     const child = @typeInfo(ptr.child);
        //     if (child == .array) {
        //         const arr = &child.array;
        //         break :blk arr.child == u8;
        //     }
        // }
        break :blk false;
    };
}

// ISSUE(https://github.com/ziglang/zig/issues/20310): Calling `std.meta.stringToEnum` directly
// fails to compile under the current version of Zig if the struct only has a single argument. This
// wrapper works around the issue.
fn stringToEnum(comptime T: type, str: []const u8) ?T {
    if (@typeInfo(T).@"enum".fields.len == 1) {
        if (std.mem.eql(u8, str, @typeInfo(T).@"enum".fields[0].name)) {
            return @enumFromInt(@typeInfo(T).@"enum".fields[0].value);
        }
        return null;
    }
    return std.meta.stringToEnum(T, str);
}

fn unsupportedType(comptime T: type) noreturn {
    const info = @typeInfo(T);
    @compileError("unsupported type '" ++ @typeName(T) ++ "' with tag '" ++ @tagName(info) ++ "'");
}

fn duplicateNameError(flag: Flag, i: usize, j: usize) noreturn {
    @compileError(std.fmt.comptimePrint("duplicate names '" ++ flag.name ++ "' at indices {} and {}.", .{ j, i }));
}

fn invalidNameError(flag: Flag, i: usize, reason: []const u8) noreturn {
    @compileError(std.fmt.comptimePrint("{s} '" ++ flag.name ++ "' at index {}", .{ reason, i }));
}

fn fmtParsedVal(
    value: anytype,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    const V = @TypeOf(value);
    switch (@typeInfo(V)) {
        .@"enum" => try writer.writeAll(@tagName(value)),
        .pointer => if (comptime isZigString(V)) {
            try writer.writeAll(value);
        } else unsupportedType(V),
        else => try std.fmt.formatType(value, fmt, options, writer, 0),
    }
}

fn debug(comptime fmt: []const u8, args: anytype) void {
    _ = fmt; // autofix
    _ = args; // autofix
    // log.debug(fmt, args);
}

const std = @import("std");
const mem = std.mem;
const meta = std.meta;
const log = std.log.scoped(.flags);
const assert = std.debug.assert;

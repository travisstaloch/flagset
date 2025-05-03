# flagset
A command line flag parsing package

# goals
Simplicity, fast compile times, and small binary size with measured use of comptime.

# features
* auto generated usage/help text
  * format width specifier controls column width.  i.e. `"{: <25}"` sets width to 25.
* positional (unnamed) flags may occur in any position, not just after named flags.  positional flags are always parsed in declaration order.
* compososition: `parse()` methods return unparsed args or a modified iterator.  this allows for composing flagsets by passing `parse_result.unparsed_args` on to further `parse()` methods with different flagsets.
  * Flag parsing stops when all flags have been parsed, just before the first non-flag argument ("-" is a non-flag argument) or after the terminator "--"
* parse into pointers by passing optional runtime `ParseOptions.ptrs` fields.  this allows for storing parse results in some existing location instead of a returned `ParseResult()`.
* custom flag parsing with `flagset.Flag.Options.parseFn`.  this also makes it possible to parse into other types such as structs.
* parse integers from utf8 strings by setting `flagset.Flag.Options.int_from_utf8`
* abbreviated short bool flags: '-abc' is parsed the same as '-a -b -c'
* accept command line args as slice or iterator with `parseFromSlice()` and `parseFromIter()`
  * supports any iterator with a `fn next() ?[]const u8` such as `std.process.args()`, `std.mem.tokenize()`, `std.mem.split()`
* supports parsing repeated flags into lists when `flag.options.kind == .list`. see `Flag.Options.kind` doc comments and tests.

# use
```console
zig fetch --save git+https://github.com/travisstaloch/flagset
```

```zig
// build.zig
const flagset_dep = b.dependency("flagset", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("flagset", flagset_dep.module("flagset"));
```

[src/demo.zig](src/demo.zig)
```zig
const std = @import("std");

const flagset = @import("flagset");

pub fn main() !void {
    const flags = [_]flagset.Flag{
        .init(bool, "flag", .{ .short = 'f', .desc = "flag description" }),
        .init(u32, "count", .{ .desc = "count description" }),
        .init(enum { one, two }, "enum", .{ .kind = .positional, .desc = "enum description" }),
        .init(?[]const u8, "opt-string", .{ .short = 's', .desc = "opt-string description" }),
        .init([]const u8, "string", .{ .desc = "string description" }),
        .init([]const u8, "pos-str", .{ .kind = .positional, .desc = "pos-str description" }),
        .init(u8, "with-default", .{ .desc = "with-default description", .default_value_ptr = &@as(u8, 10) }),
        .init([]const u8, "list", .{ .desc = "list description", .kind = .list }),
    };

    const alloc = std.heap.page_allocator; // TODO use a better allocator
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var result = flagset.parseFromIter(&flags, args, .{ .allocator = alloc }) catch |e| switch (e) {
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
    std.debug.print("parsed: {}\n", .{flagset.fmtParsed(&flags, result.parsed, .{})});
    std.debug.print("unparsed args: ", .{});
    while (result.unparsed_args.next()) |arg| std.debug.print("{s} ", .{arg});
    std.debug.print("\n", .{});
}
```
```console
$ zig build demo -- -h

usage: demo <options>

options:
  --help, -h                                 show this message and exit
  --flag, --no-flag, -f                      flag description
  --count <u32>                              count description
  <enum:one|two>                             enum description
  --opt-string, --no-opt-string, -s <string> opt-string description
  --string <string>                          string description
  <pos-str:string>                           pos-str description
  --with-default <u8>                        with-default description
  --list <string> (many)                     list description

$ zig build demo -- --flag --count 10 two --no-opt-string --string "s" pos-str --list foo --list bar --foo --bar
parsed: --flag --count 10 two --no-opt-string --string s pos-str --with-default 10 --list foo --list bar
unparsed args: --foo --bar 

```

# more examples
* [src/tests.zig](src/tests.zig)

# references
* https://github.com/Games-by-Mason/structopt
* https://pkg.go.dev/flag

# todo
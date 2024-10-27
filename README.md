# flagset
A command line flag parsing package

# goals
Simplicity, fast compile times, and small binary size with measured use of comptime.

# features
* auto generated usage/help text
  * format width specifier controls column width.  i.e. `"{: <25}"` sets width to 25.
* accept command line args as slice or iterator with `parseFromSlice()` and `parseFromIter()`
  * supports any iterator with a `fn next() ?[]const u8` such as `std.process.args()`, `std.mem.tokenize()`, `std.mem.split()`
* positional (unnamed) flags may occur in any position, not just after named flags.  positional flags are always parsed in declaration order.
* compososition: `parse()` methods return unparsed args or a modified iterator.  this allows for composing flagsets by passing `parse_result.unparsed_args` on to other flagsets.
  * Flag parsing stops just before the first non-flag argument ("-" is a non-flag argument) or after the terminator "--"
* parse into pointers with `parseFromSliceIntoPtrs()` and `parseFromIterIntoPtrs()`
* custom flag parsing with `flagset.Flag.Options.parseFn`.  this also makes it possible to parse into a struct.
* parse integers from utf8 strings by setting `flagset.Flag.Options.int_from_utf8`

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

from [src/demo.zig](src/demo.zig)

```zig
// demo.zig
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
```
```console
$ zig build demo -- -h

usage: demo <options>

options:
  --help, -h                                 show this message and exit
  --flag, --no-flag, -f                      flag help
  --count <u32>                              count help
  <enum:one|two>                             enum help
  --opt-string, --no-opt-string, -s <string> opt-string help
  --string <string>                          string help
  <pos-str:string>                           pos-str help

$ zig build demo -- --flag --count 10 two --no-opt-string --string "s" pos-str
parsed: --flag --count 10 two --no-opt-string --string s pos-str
```

# more examples
* [src/tests.zig](src/tests.zig)

# references
* https://github.com/Games-by-Mason/structopt
* https://pkg.go.dev/flag

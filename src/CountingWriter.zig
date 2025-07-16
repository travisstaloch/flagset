//! Copyright (c) 2025 github.com/silversquirl
//!
//! A Writer that counts how many bytes have been written to it.

// TODO - switch to some std impl of this stuff once it either gains a post
// writergate Io.CountingWriter or Io.MultiWriter.

const Counting = @This();

count: i65 = 0,
child: *Writer,
writer: Writer,

pub fn init(child: *Writer) Writer.Error!Counting {
    var w: Counting = .{
        .child = child,
        .writer = .{
            .buffer = undefined,
            .vtable = comptime &.{
                .drain = drain,
                .sendFile = sendFile,
                .flush = flush,
            },
        },
    };
    // Steal the child's buffer
    stealBuffer(&w.writer, child);
    w.count = -@as(i65, w.writer.end);
    return w;
}

pub fn deinit(w: *Counting) void {
    // Give the buffer back
    w.count += w.writer.end;
    stealBuffer(w.child, &w.writer);
}

pub fn logicalCount(w: Counting) u64 {
    return @intCast(w.count + w.writer.end);
}

fn drain(io_w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const w: *Counting = @alignCast(@fieldParentPtr("writer", io_w));
    stealBuffer(w.child, &w.writer);
    defer stealBuffer(&w.writer, w.child);

    const end = w.child.end;
    const count = try w.child.vtable.drain(w.child, data, splat);
    w.count += count + end - w.child.end;
    return count;
}

fn sendFile(io_w: *Writer, file_reader: *std.fs.File.Reader, limit: std.Io.Limit) Writer.FileError!usize {
    const w: *Counting = @alignCast(@fieldParentPtr("writer", io_w));
    stealBuffer(w.child, &w.writer);
    defer stealBuffer(&w.writer, w.child);

    const end = w.child.end;
    const count = try w.child.vtable.sendFile(w.child, file_reader, limit);
    w.count += count + end - w.child.end;
    return count;
}

fn flush(io_w: *Writer) Writer.Error!void {
    const w: *Counting = @alignCast(@fieldParentPtr("writer", io_w));
    stealBuffer(w.child, &w.writer);
    defer stealBuffer(&w.writer, w.child);

    const end = w.child.end;
    try w.child.flush();
    w.count += end - w.child.end;
}

fn stealBuffer(to: *Writer, from: *Writer) void {
    to.buffer = from.buffer;
    to.end = from.end;

    from.buffer = &.{};
    from.end = 0;
}

// TODO: this only really tests `drain`
test Counting {
    var buf: [1 << 10]u8 = undefined;
    var fixed: Writer = .fixed(&buf);
    var cw: Counting = try .init(&fixed);

    // TODO: write a test that actually uses a file
    // var buf: [16]u8 = undefined;
    // var stdout = std.fs.File.stdout().writer(&buf);
    // var cw: Counting = try .init(&stdout.interface);

    var count: usize = 0;
    try cw.writer.writeAll("Hello, world!");
    count += "Hello, world!".len;
    try std.testing.expectEqual(count, cw.logicalCount());

    try cw.writer.writeAll(" stuff");
    count += " stuff".len;
    try std.testing.expectEqual(count, cw.logicalCount());

    try cw.writer.writeByte('\n');
    count += 1;
    try std.testing.expectEqual(count, cw.logicalCount());
    try cw.writer.flush();

    cw.deinit();

    try std.testing.expectEqualStrings("Hello, world! stuff\n", fixed.buffered());
    try std.testing.expectEqual(fixed.end, cw.count);
    try std.testing.expectEqual(cw.count, cw.logicalCount());
}

test "Counting works with a partially filled buffer" {
    var buf: [1 << 10]u8 = undefined;
    var fixed: Writer = .fixed(&buf);
    try fixed.writeAll("Hello, world!");

    var cw: Counting = try .init(&fixed);
    try std.testing.expectEqual(0, cw.logicalCount());
    try cw.writer.writeAll("hi again");
    try std.testing.expectEqual("hi again".len, cw.logicalCount());
}

const std = @import("std");
const Writer = std.Io.Writer;

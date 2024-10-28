pub fn StaticBitsetMap(comptime bit_count: u16, comptime V: type) type {
    return struct {
        bitset: BitSet,
        values: []V,

        const Self = @This();
        pub const BitSet = std.meta.Int(.unsigned, bit_count);
        pub const K = std.math.Log2Int(BitSet);

        pub fn initEmpty(buf: []V) Self {
            return .{ .bitset = 0, .values = buf };
        }

        pub fn get(sset: Self, key: K) ?V {
            return if (sset.getIndex(key)) |index|
                sset.values[index]
            else
                null;
        }

        pub fn set(sset: *Self, key: K, value: V) void {
            const len = sset.count();
            sset.setBit(key);
            const index = sset.getIndex(key).?;
            if (index < len) {
                const ptr = sset.values.ptr + index;
                std.mem.copyBackwards(
                    V,
                    (ptr + 1)[0 .. len - index],
                    ptr[0 .. len - index],
                );
            }
            sset.values[index] = value;
        }

        pub fn isSet(sset: Self, key: K) bool {
            return @as(u1, @truncate(sset.bitset >> key)) != 0;
        }

        pub fn count(sset: Self) u16 {
            return @popCount(sset.bitset);
        }

        fn setBit(sset: *Self, key: K) void {
            sset.bitset |= @as(BitSet, 1) << key;
        }

        pub fn getIndex(sset: Self, key: K) ?K {
            if (sset.isSet(key)) {
                if (true) {
                    // TODO: benchmark which is faster.
                    // this method results in fewer instructions when bit_count = 256.
                    const bits = @bitSizeOf(usize);
                    const ok = bits >= std.math.maxInt(K);
                    const len = if (ok) 0 else key / bits;
                    const rem: u6 = if (ok) @intCast(key) else @intCast(key % bits);
                    var index: K = 0;
                    const masks_len = (bit_count + bits - 1) / bits;
                    const I = std.meta.Int(.unsigned, masks_len * bits);
                    const masks: [masks_len]usize = @bitCast(@as(I, sset.bitset));
                    inline for (0..masks_len - 1) |i| {
                        index += @popCount(masks[i]) * @intFromBool(len > i);
                    }
                    const x = (@as(usize, 1) << rem) - 1;
                    index += @intCast(@popCount(masks[len] & x) * @intFromBool(rem != 0));
                    return index;
                } else {
                    return @intCast(@popCount(sset.bitset & (@as(u256, 1) << key) - 1));
                }
            }
            return null;
        }
    };
}
const std = @import("std");
const assert = std.debug.assert;

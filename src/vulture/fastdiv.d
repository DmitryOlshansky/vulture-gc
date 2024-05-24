module vulture.fastdiv;

import std.conv;

pure nothrow:

// only for small integers
size_t multiplier(size_t div) @nogc {
    return cast(size_t)(((1L<<32) + div) * 1.0 / div);
}

pragma(inline, true)
size_t divide(size_t value, size_t mult) @nogc {
    return (value * mult) >> 32;
}


version(vulture_fastdiv) 
unittest {
    foreach (divisor; 1..2049) {
        size_t mult = multiplier(divisor);
        foreach (dividend; 0..2<<20) {
            assert(dividend / divisor == divide(dividend, mult), text(
                "Divide ", dividend, " by ", divisor, " ",
                 dividend / divisor, " != ", divide(dividend, mult))
            );
        }
    }
}
module vulture.size_class;

immutable size_t[] sizeClasses = [
    16,
    24,
    32,
    48,
    64,
    96,
    128,
    192,
    256,
    384,
    512,
    768,
    1024,
    1536,
    2048
];

enum {
    MAX_SMALL_SIZE = sizeClasses[$-1]
}

pure nothrow @nogc:

bool isSmall(size_t size) {
    return size <= MAX_SMALL_SIZE;
}

ubyte slowSizeToClass(size_t size) {
    foreach (clazz, sz; sizeClasses) {
        if (size <= sz) {
            return cast(ubyte)clazz;
        }
    }
    assert(0, "Expected small size for size toSizeClass");
}

ubyte[MAX_SMALL_SIZE+1] generateSizeClassesTable() {
    ubyte[MAX_SMALL_SIZE+1] table;
    foreach (i; 0 .. MAX_SMALL_SIZE+1) {
        table[i] = slowSizeToClass(i);
    }
    return table;
}

immutable ubyte[MAX_SMALL_SIZE+1] sizeClassesTable = generateSizeClassesTable();

ubyte sizeToClass(size_t size) {
    if (size > MAX_SMALL_SIZE) assert(0, "Expected small size for size toSizeClass");
    return sizeClassesTable.ptr[size];
}

size_t classToSize(ubyte clazz) {
    return sizeClasses[clazz];
}
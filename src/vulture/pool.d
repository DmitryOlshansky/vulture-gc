module vulture.pool;

static import core.memory;
import core.bitop;
import core.internal.spinlock;
import core.stdc.string;
debug(vulture) import core.stdc.stdio;

import vulture.bits, vulture.size_class, vulture.memory;

package:
nothrow  @nogc:

enum {
    CHUNKSIZE = 512 * PAGESIZE,
    MAXSMALL = 2048,
    MAXLARGE = 8 * CHUNKSIZE, 
    SMALL_BATCH_SIZE = 32
}

alias BlkInfo = core.memory.GC.BlkInfo;
alias BlkAttr = core.memory.GC.BlkAttr;

enum PoolType {
    NONE = 0,
    SMALL = 1, // up to 2K
    LARGE = 2, // from 2k+ to 8M
    HUGE = 3   // 8M+
}

// Buckets for Large pool
enum BUCKETS = (toPow2(MAXLARGE) - 12 + 3) / 4;

enum NibbleAttr : ubyte {
    FINALIZE = 0x1,
    APPENDABLE = 0x2,
    NO_INTERIOR = 0x4,
    STRUCTFINAL = 0x8
}

uint attrFromNibble(ubyte nibble, bool noScan) nothrow pure {
    uint attr;
    if (nibble & NibbleAttr.FINALIZE) attr |= BlkAttr.FINALIZE;
    if (nibble & NibbleAttr.APPENDABLE) attr |= BlkAttr.APPENDABLE;
    if (nibble & NibbleAttr.NO_INTERIOR) attr |= BlkAttr.NO_INTERIOR;
    if (nibble & NibbleAttr.STRUCTFINAL) attr |= BlkAttr.STRUCTFINAL;
    if (noScan) attr |= BlkAttr.NO_SCAN;
    return attr;
}

ubyte attrToNibble(uint attr) nothrow pure {
    ubyte nibble;
    if (attr & BlkAttr.FINALIZE) nibble |= NibbleAttr.FINALIZE;
    if (attr & BlkAttr.APPENDABLE) nibble |= NibbleAttr.APPENDABLE;
    if (attr & BlkAttr.NO_INTERIOR) nibble |= NibbleAttr.NO_INTERIOR;
    if (attr & BlkAttr.STRUCTFINAL) nibble |= BlkAttr.STRUCTFINAL;
    return nibble;
}

ubyte toPow2(size_t size) nothrow pure {
    ubyte notPow2 = (size & (size-1)) != 0;
    return cast(ubyte)(notPow2 + bsr(size));
}

ubyte bucketOf(size_t size) nothrow {
    ubyte pow2 = toPow2(size);
    assert(pow2 >= 12); // 4K+ in large pool
    ubyte bucket = cast(ubyte)((pow2 - 12) / 4);
    return bucket > BUCKETS-1 ? BUCKETS-1 : bucket;
}

/// Segregated pool with a single size class.
/// Memory is allocated in bulk - 32 objects at a time.
struct SmallPool
{
    uint objects;      // total objects
    uint objectSize;   // size of objects in this pool
    uint nextFree;     // index of next free object batch
    BitArray markbits; // granularity is per object
    ubyte* attrs;      // granularity is per object
}

struct SmallAlloc {
    void* next;
    ubyte* attrsPtr;
}

struct SmallAllocBatch {
    SmallAlloc* head;
    SmallAlloc* tail;
}

/// A set of pages organized into a bunch of free lists
/// by size ranges. Granularity is 4K.
struct LargePool
{
    uint largestFreeEstimate; // strictly >= largest free block, in bytes
    uint pages; // number of pages in this pool
    uint[BUCKETS] buckets; // index of the first free run
    // offset serves double duty
    // when pages are free it contains next in a free list
    // else it is filled with offset of start of the object
    uint* offsetTable; // one uint per page
    // size of an object or a run of free pages, in 4k pages
    uint* sizeTable; // one uint per page
    BitArray markbits;
    ubyte* attrs;
}

/// A "pool" that represents single huge allocation.
/// All requests to realloc or extend are forwarded to
/// respective OS primitives. Granularity is one chunk - 2MB.
struct HugePool
{
    size_t size;
    bool mark;
    bool finals;
    bool structFinals;
    bool appendable;
}

struct Pool
{
    union Impl
    {
        SmallPool small;
        LargePool large;
        HugePool huge;
    }
    shared SpinLock _lock;  // per pool lock
    PoolType type;          // type of pool (immutable)
    bool isFree;            // if this pool is completely free
    bool noScan;            // if objects of this pool have no pointers (immutable)
    Impl impl;              // concrete pool details
    void[] mapped;          // real region covered by this pool, immutable
    Pool* next;             // freelist link
nothrow @nogc:

    @property ref small(){ return impl.small; }
    @property ref large(){ return impl.large; }
    @property ref huge(){ return impl.huge; }

    void initializeSmall(ubyte clazz, bool noScan)
    {
        _lock = shared(SpinLock)(SpinLock.Contention.medium);
        isFree = true;
        this.noScan = noScan;
        this.type = PoolType.SMALL;
        small.objectSize = cast(uint)classToSize(clazz);
        small.objects = cast(uint)mapped.length / small.objectSize;
        small.nextFree = 0;
        small.attrs = cast(ubyte*)mapMemory(small.objectSize).ptr;
        //TODO: allocate bits
    }

    void initializeLarge(bool noScan) {
        type = PoolType.LARGE;
        this.noScan = noScan;
        large.largestFreeEstimate = cast(uint)(mapped.length);
        large.pages = cast(uint)(mapped.length / PAGESIZE);
        large.buckets[] = uint.max;
        large.offsetTable = cast(uint*)mapMemory(uint.sizeof *large.pages).ptr;
        large.sizeTable = cast(uint*)mapMemory(uint.sizeof * large.pages).ptr;
        //TODO: allocate bits
        large.attrs = cast(ubyte*)mapMemory(large.pages).ptr;
        // setup free lists as one big chunk of highest bucket
        large.sizeTable[0] = (large.largestFreeEstimate + PAGESIZE-1) / PAGESIZE;
        large.offsetTable[0] = uint.max;
        large.buckets[BUCKETS-1] = 0;

    }

    void lock(){ _lock.lock(); }

    void unlock(){ _lock.unlock(); }

//TODO: incapsulate tagged dispatch
    uint getAttr(void* p)
    {
        if (type == PoolType.SMALL) return getAttrSmall(p);
        else if(type == PoolType.LARGE) return getAttrLarge(p);
        else return getAttrHuge(p);
    }

    uint setAttr(void* p, uint attrs)
    {
        if (type == PoolType.SMALL) return setAttrSmall(p, attrs);
        else if(type == PoolType.LARGE) return setAttrLarge(p, attrs);
        else return setAttrHuge(p, attrs);
    }

    uint clrAttr(void* p, uint attrs)
    {
        if (type == PoolType.SMALL) return clrAttrSmall(p, attrs);
        else if(type == PoolType.LARGE) return clrAttrLarge(p, attrs);
        else return clrAttrHuge(p, attrs);
    }

    size_t sizeOf(void* p)
    {
        if (type == PoolType.SMALL) return sizeOfSmall(p);
        else if(type == PoolType.LARGE) return sizeOfLarge(p);
        else return sizeOfHuge(p);
    }

    void* addrOf(void* p)
    {
        if (type == PoolType.SMALL) return addrOfSmall(p);
        else if(type == PoolType.LARGE) return addrOfLarge(p);
        else return addrOfHuge(p);
    }

    // uint.max means same bits
    BlkInfo tryExtend(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        if (type == PoolType.SMALL)
            return tryExtendSmall(p, minSize, maxSize, bits);
        else if(type == PoolType.LARGE)
            return tryExtendLarge(p, minSize, maxSize, bits);
        else
            return tryExtendHuge(p, minSize, maxSize, bits);
    }

    BlkInfo query(void* p)
    {
        if (type == PoolType.SMALL) return querySmall(p);
        else if(type == PoolType.LARGE) return queryLarge(p);
        else return queryHuge(p);
    }

    void free(void* p)
    {
        assert(type != PoolType.HUGE); // Huge is handled separately
        if (type == PoolType.SMALL) return freeSmall(p);
        else return freeLarge(p);
    }

    void runFinalizers(const void[] segment) {
        // TODO
    }

// SMALL POOL implementations
    // small allocates in batches
    SmallAllocBatch allocateSmall() {
        auto remaining = small.objects - small.nextFree;
        size_t batchSize = remaining > SMALL_BATCH_SIZE ? SMALL_BATCH_SIZE : remaining;
        if (batchSize == 0) return SmallAllocBatch(null, null);
        size_t size = small.objectSize;
        void* start = cast(SmallAlloc*)(mapped.ptr + small.nextFree * size);
        void* end = start + batchSize * size;
        debug(vulture) printf("smallAlloc %p %p\n", mapped.ptr, mapped.ptr + mapped.length);
        ubyte* attrsPtr = small.attrs + small.nextFree;
        for(void* p = start; p < end; p += size) {
            auto sp = cast(SmallAlloc*)p;
            if (p != end - size) {
                sp.next = p + size;
            }
            else {
                sp.next = null;
            }
            sp.attrsPtr = attrsPtr++;
        }
        small.nextFree += batchSize;
        debug(vulture) printf("smallAlloc %p %p\n", start, end);
        return SmallAllocBatch(cast(SmallAlloc*)start, cast(SmallAlloc*)(end - size));
    }

    uint getAttrSmall(void* p) {
        uint offset = cast(uint)(p - mapped.ptr) / small.objectSize;
        return attrFromNibble(small.attrs[offset], noScan);
    }

    uint setAttrSmall(void* p, uint attrs) {
        uint offset = cast(uint)(p - mapped.ptr) / small.objectSize;
        small.attrs[offset] |= cast(ubyte)attrToNibble(attrs);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    uint clrAttrSmall(void* p, uint attrs) {
        uint offset = cast(uint)(p - mapped.ptr) / small.objectSize;
        small.attrs[offset] &= cast(ubyte)~attrToNibble(attrs);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    size_t sizeOfSmall(void* p) {
        return small.objectSize;
    }

    void* addrOfSmall(void* p) {
        auto roundedDown = cast(size_t)p - cast(size_t)p % small.objectSize;
        return cast(void*)roundedDown;
    }

    // uint.max means same bits
    BlkInfo tryExtendSmall(void* p, size_t minSize, size_t maxSize, uint bits=uint.max) {
        size_t ourSize = small.objectSize;
        if (minSize < ourSize) {
            size_t newSize = ourSize > maxSize ? maxSize : ourSize;
            uint offset = cast(uint)(p - mapped.ptr) / ourSize;
            if (bits != uint.max)
                small.attrs[offset] = attrToNibble(bits);
            return BlkInfo(p, newSize, attrFromNibble(small.attrs[offset], noScan));
        }
        return BlkInfo.init;
    }

    BlkInfo querySmall(void* p) {
        void* base = addrOfSmall(p);
        uint offset = cast(uint)(p - mapped.ptr) / small.objectSize;
        return BlkInfo(base, small.objectSize, attrFromNibble(small.attrs[offset], noScan));
    }

    void freeSmall(void* p) {
        uint offset = cast(uint)(p - mapped.ptr) / small.objectSize;
        small.attrs[offset] = 0;
    }

// LARGE POOL implementations
    uint startOfLarge(void* p)
    {
        uint i = cast(uint)(p - mapped.ptr) / PAGESIZE;
        return large.offsetTable[i];
    }

    void putToFreeList(uint offset, uint psize)
    {
        ubyte bucket = bucketOf(psize * PAGESIZE);
        large.offsetTable[offset] = large.buckets[bucket];
        large.sizeTable[offset] = psize;
        large.buckets[bucket] = offset;
    }

    BlkInfo allocateLarge(size_t size, uint bits)
    {
        assert(type == PoolType.LARGE);
        ubyte bucket = bucketOf(size);
        uint psize = cast(uint)(size + PAGESIZE-1) / PAGESIZE;

        BlkInfo cutOut(uint start) nothrow
        {
            for (uint i = start; i < start + psize; i++)
                large.offsetTable[i] = start;
            large.sizeTable[start] = psize;
            BlkInfo blk;
            blk.base = mapped.ptr + start*PAGESIZE;
            blk.size = psize * PAGESIZE;
            blk.attr = bits;
            // TODO: set attr metadata
            debug(vulture) printf("large.attrs = %p\n", large.attrs);
            large.attrs[start] = attrToNibble(bits);
            return blk;
        }

        uint head = large.buckets[bucket];
        uint cur = head, prev = head;
        while (cur != uint.max)
        {
            uint blockSize = large.sizeTable[cur];
            if (blockSize >= psize)
            {
                if (cur == head) large.buckets[bucket] = large.offsetTable[cur];
                else large.offsetTable[prev] = large.offsetTable[cur];
                uint rem = blockSize - psize;
                if (rem) putToFreeList(cur + psize, rem);
                return cutOut(cur);
            }
            prev = cur;
            cur = large.offsetTable[cur];
        }
        debug(vulture) printf("Looking for larger buckets\n");
        bucket++;
        // search larger buckets
        while (bucket < BUCKETS)
        {
            if (large.buckets[bucket] != uint.max)
            {
                uint s = large.buckets[bucket];
                large.buckets[bucket] = large.offsetTable[s];
                uint blockSize = large.sizeTable[s];
                uint rem = blockSize - psize;
                assert(rem > 0);
                putToFreeList(s + psize, rem);
                return cutOut(s);
            }
            bucket++;
        }
        // not found
        return BlkInfo.init;
    }

    uint getAttrLarge(void* p)
    {
        uint s = startOfLarge(p);
        return attrFromNibble(large.attrs[s], noScan);
    }

    uint setAttrLarge(void* p, uint attrs)
    {
        uint s = startOfLarge(p);
        large.attrs[s] |= attrToNibble(attrs);
        return attrFromNibble(large.attrs[s], noScan);
    }

    uint clrAttrLarge(void* p, uint attrs)
    {
        uint s = startOfLarge(p);
        large.attrs[s] &= cast(ubyte)~attrToNibble(attrs);
        return attrFromNibble(large.attrs[s],noScan);
    }

    size_t sizeOfLarge(void* p)
    {
        uint s = startOfLarge(p);
        return large.sizeTable[s];
    }

    void* addrOfLarge(void* p)
    {
        return mapped.ptr + startOfLarge(p)*PAGESIZE;
    }

    // uint.max means same bits
    BlkInfo tryExtendLarge(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        //TODO: check if followed by free space, extend + readd it from free lists
        return BlkInfo.init;
    }

    BlkInfo queryLarge(void* p)
    {
        uint s = startOfLarge(p);
        void* base = mapped.ptr + s*PAGESIZE;
        uint size = large.sizeTable[s]*PAGESIZE;
        uint attrs = attrFromNibble(large.attrs[s], noScan);
        return BlkInfo(base, size, attrs);
    }

    void freeLarge(void* p)
    {
        uint s = startOfLarge(p);
        uint psize = large.sizeTable[s];
        putToFreeList(s, psize);
        large.attrs[s] = 0;
    }

// HUGE POOL implementations
    uint getAttrHuge(void* p)
    {
        uint attrs;
        if (huge.finals) attrs |= BlkAttr.FINALIZE;
        if (huge.appendable) attrs |= BlkAttr.APPENDABLE;
        if (huge.structFinals) attrs |= BlkAttr.STRUCTFINAL;
        if (noScan) attrs |= BlkAttr.NO_SCAN;
        return attrs;
    }

    uint setAttrHuge(void* p, uint attrs)
    {
        if (attrs & BlkAttr.FINALIZE) huge.finals = true;
        if (attrs & BlkAttr.APPENDABLE) huge.appendable = true;
        if (attrs & BlkAttr.STRUCTFINAL) huge.structFinals = true;
        return getAttrHuge(p);
    }

    uint clrAttrHuge(void* p, uint attrs)
    {
        if (attrs & BlkAttr.FINALIZE) huge.finals = false;
        if (attrs & BlkAttr.APPENDABLE) huge.appendable = false;
        if (attrs & BlkAttr.STRUCTFINAL) huge.structFinals = false;
        return getAttrHuge(p);
    }

    size_t sizeOfHuge(void* p)
    {
        return huge.size;
    }

    void* addrOfHuge(void* p)
    {
        return mapped.ptr;
    }

    // uint.max means same bits
    BlkInfo tryExtendHuge(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        //TODO: use mremap on *NIX
        return BlkInfo.init;
    }

    BlkInfo queryHuge(void* p)
    {
        size_t size = huge.size;
        uint attrs = getAttrHuge(p);
        return BlkInfo(mapped.ptr, size, attrs);
    }
}

/*

Pool* newHugePool(size_t size, uint bits) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.HUGE;
    p.shiftBy = 20;
    p.noScan = ((bits & BlkAttr.NO_SCAN) != 0);
    p.initialize(size);
    p.isFree = false;
    p.huge.finals = ((bits & BlkAttr.FINALIZE) != 0);
    p.huge.structFinals = ((bits & BlkAttr.STRUCTFINAL) != 0);
    p.huge.appendable = ((bits & BlkAttr.APPENDABLE) != 0);
    return p;
}

unittest
{
    Pool* pool = newSmallPool(5, true);

}


unittest
{
    enum size = 12*CHUNKSIZE;
    Pool* pool = newLargePool(size, true);
    foreach_reverse(item; 1..1000)
    {
        size_t itemSize = item*PAGESIZE;
        struct Link
        {
            Link* next;
        }
        Link* head = null;
        size_t cnt = 0;
        for(;;cnt++)
        {
            BlkInfo blk = pool.allocateLarge(itemSize, 0);
            if (!blk.base) break;
            Link* n = cast(Link*)blk.base;
            assert(blk.base);
            assert(blk.size == itemSize);
            n.next = head;
            head = n;
        }
        assert(cnt >= size/1000/PAGESIZE);
        if (item == 1)
            assert(cnt == size/PAGESIZE);
        while(head)
        {
            Link* cur = head;
            head = head.next;
            pool.freeLarge(cur);
        }
    }
}
*/
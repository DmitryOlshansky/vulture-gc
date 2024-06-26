module vulture.pool;

static import core.memory;
import core.bitop;
import core.atomic;
import core.stdc.string;
debug(vulture) import core.stdc.stdio;
debug(vulture_sweep) import core.stdc.stdio;
import core.thread.threadbase;

import vulture.size_class, vulture.memory, vulture.fastdiv, vulture.spinlock;

package:
nothrow  @nogc:

enum {
    CHUNKSIZE = 2048 << 10,
    MAXSMALL = 2048,
    MAXLARGE = 8 * CHUNKSIZE
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

uint attrFromNibble(ubyte nibble, bool noScan) nothrow pure {
    return nibble | (noScan ? BlkAttr.NO_SCAN : 0);
}

ubyte attrToNibble(uint attr) nothrow pure {
    return cast(ubyte)attr;
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
    size_t multiplier; // fast div multiplier
    size_t* allocBits; // bits of allocated objects
    size_t* markBits;  // bits of marked objects
    ubyte* attrs;      // granularity is per object
}

struct SmallAlloc {
    void* ptr;
    ubyte* attrs;
}

struct SmallAllocBatch {
    void[] memory;
    ubyte* attrs;
    size_t size;
    void* ptr;
    size_t mask;
    size_t allocBits;

    SmallAlloc alloc() nothrow pure @nogc {
        while (ptr != null) {
            debug(vulture) printf("mask = %lx ptr = %p\n", mask, ptr);
            if (!(mask & allocBits)) {
                auto ret = ptr;
                auto attrsRet = attrs;
                ptr += size;
                attrs++;
                if (mask == (1UL<<63)) {
                    ptr = null;
                } else {
                    mask <<= 1;
                }
                debug(vulture) printf("Allocated tcache mask = %lx ptr = %p\n", mask, ptr);
                return SmallAlloc(ret, attrsRet);
            }
            if (mask == (1UL<<63)) {
                ptr = null;
                break;
            } else {
                mask <<= 1;
            }
            attrs++;
            ptr += size;
            
        }
        return SmallAlloc.init;
    }
}

/// A set of pages organized into a bunch of free lists
/// by size ranges. Granularity is 4K.
struct LargePool {
    uint pages;               // number of pages in this pool
    uint[BUCKETS] buckets;    // index of the first free run
    // offset serves double duty
    // when pages are free it contains next in a free list
    // else it is filled with offset of start of the object
    uint* offsetTable;        // one uint per page
    // size of an object or a run of free pages, in 4k pages
    uint* sizeTable;          // one uint per page
    ubyte* markBits;          // bits used while marking, one bit per page
    ubyte* attrs;             // attributes one byte per page
}

/// A "pool" that represents single huge allocation.
/// All requests to realloc or extend are forwarded to
/// respective OS primitives. Granularity is one chunk - 2MB.
struct HugePool {
    size_t size;
    bool mark;
    bool finals;
    bool structFinals;
    bool appendable;
}

struct Pool {
    union Impl {
        SmallPool small;
        LargePool large;
        HugePool huge;
    }
    shared AlignedSpinLock _lock;  // per pool lock
    PoolType type;          // type of pool (immutable)
    bool noScan;            // if objects of this pool have no pointers (immutable)
    Impl impl;              // concrete pool details
    void[] mapped;          // real region covered by this pool, immutable
    Pool* next;             // freelist link
nothrow @nogc:

    @property ref small(){ return impl.small; }
    @property ref large(){ return impl.large; }
    @property ref huge(){ return impl.huge; }

    void initializeSmall(ubyte clazz, bool noScan) {
        this.noScan = noScan;
        small.objectSize = cast(uint)classToSize(clazz);
        small.objects = cast(uint)mapped.length / small.objectSize;
        small.multiplier = multiplier(small.objectSize);
        small.nextFree = 0;
        small.attrs = cast(ubyte*)mapMemory(small.objects).ptr;
        small.markBits = cast(size_t*)mapMemory((small.objects + 7) / 8).ptr;
        small.allocBits = cast(size_t*)mapMemory((small.objects + 7) / 8).ptr;
        atomicStore(this.type, PoolType.SMALL);
    }

    void initializeLarge(bool noScan) {
        this.noScan = noScan;
        large.pages = cast(uint)(mapped.length / PAGESIZE);
        large.buckets[] = uint.max;
        large.offsetTable = cast(uint*)mapMemory(uint.sizeof *large.pages).ptr;
        large.sizeTable = cast(uint*)mapMemory(uint.sizeof * large.pages).ptr;
        large.attrs = cast(ubyte*)mapMemory(large.pages).ptr;
        large.markBits = cast(ubyte*)mapMemory(large.pages).ptr;
        // setup free lists as one big chunk of highest bucket
        large.sizeTable[0] = cast(uint)((mapped.length + PAGESIZE-1) / PAGESIZE);
        large.offsetTable[0] = uint.max;
        large.buckets[BUCKETS-1] = 0;
        atomicStore(type, PoolType.LARGE);
    }

    void initializeHuge(size_t size, uint bits) {
        type = PoolType.HUGE;
        this.noScan = (bits & BlkAttr.NO_SCAN) != 0;
        huge.mark = 0;
        huge.size = size;
        huge.finals = ((bits & BlkAttr.FINALIZE) != 0);
        huge.structFinals = ((bits & BlkAttr.STRUCTFINAL) != 0);
        huge.appendable = ((bits & BlkAttr.APPENDABLE) != 0);
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

    void[] mark(void* p) {
        if (type == PoolType.SMALL) return markSmall(p);
        else if (type == PoolType.LARGE) return markLarge(p);
        else {
            if (huge.mark) return null;
            huge.mark = true;
            return mapped[0..huge.size];
        }
        assert(0);
    }

    IsMarked isMarked(void *p) {
        if (type == PoolType.SMALL) return isMarkedSmall(p);
        else if (type == PoolType.LARGE) return isMarkedLarge(p);
        else {
            return huge.mark ? IsMarked.yes : IsMarked.no;
        }
    }

    // uint.max means same bits
    BlkInfo tryExtend(void* p, size_t minSize, size_t maxSize, uint bits=uint.max) {
        if (type == PoolType.SMALL)
            return tryExtendSmall(p, minSize, maxSize, bits);
        else if(type == PoolType.LARGE)
            return tryExtendLarge(p, minSize, maxSize, bits);
        else
            return tryExtendHuge(p, minSize, maxSize, bits);
    }

    BlkInfo query(void* p) {
        if (type == PoolType.SMALL) return querySmall(p);
        else if(type == PoolType.LARGE) return queryLarge(p);
        else return queryHuge(p);
    }
    
    void resetMarkBits() {
        if (type == PoolType.SMALL) return resetMarkBitsSmall();
        else if (type == PoolType.LARGE) return resetMarkBitsLarge();
        else {
            huge.mark = false;
        }
    }

    void runFinalizers(const void[] segment) {
        // TODO
    }

// SMALL POOL implementations
    // small allocates in batches
    SmallAllocBatch allocateSmall(ref size_t allocated) {
        debug(vulture) printf("smallAlloc %p %p\n", mapped.ptr, mapped.ptr + mapped.length);
        for (size_t i = small.nextFree; i < small.objects; i+= 64) {
            size_t allocWord = small.allocBits[i / 64];
            if (allocWord != size_t.max) {
                small.allocBits[i / 64] = size_t.max;
                small.nextFree = cast(uint)i + 64;
                size_t size = small.objectSize;
                allocated = 64 - popcnt(allocWord);
                auto ptr = mapped.ptr + i * size;
                return SmallAllocBatch(ptr[0 .. 64 * size], small.attrs + i, size, ptr, 1, allocWord);
            }
        }
        small.nextFree = small.objects;
        return SmallAllocBatch.init;
    }

    uint getAttrSmall(void* p) {
        uint offset = indexOfSmall(p);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    uint setAttrSmall(void* p, uint attrs) {
        uint offset = indexOfSmall(p);
        small.attrs[offset] |= cast(ubyte)attrToNibble(attrs);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    uint clrAttrSmall(void* p, uint attrs) {
        uint offset = indexOfSmall(p);
        small.attrs[offset] &= cast(ubyte)~attrToNibble(attrs);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    size_t sizeOfSmall(void* p) {
        return small.objectSize;
    }

    void* addrOfSmall(void* p) {
        auto roundedDown = cast(size_t)mapped.ptr + indexOfSmall(p) * small.objectSize;
        return cast(void*)roundedDown;
    }

    pragma(inline, true)
    uint indexOfSmall(void* p) {
        return cast(uint)divide(p - mapped.ptr, small.objectSize);
    }

    void[] markSmall(void* p) {
        auto size = small.objectSize;
        auto idx = divide(p - mapped.ptr, size);
        auto b = idx/64;
        auto mask = 1UL<<(idx % 64);
        if (small.markBits[b] & mask) return null;
        small.markBits[b] |= mask;
        if (noScan) return null;
        size_t offset = idx * size;
        return mapped[offset .. offset + size];
    }

    IsMarked isMarkedSmall(void *p) {
        auto size = small.objectSize;
        auto idx = divide(p - mapped.ptr, size);
        auto b = idx/64;
        auto mask = 1UL<<(idx % 64);
        return small.markBits[b] & mask ? IsMarked.yes : IsMarked.no;
    }

    void sweepSmall(ref size_t freed, ref size_t used) {
        size_t freedLocal = 0, usedLocal = 0;
        size_t len = (small.objects + 63) / 64;
        for (size_t i = 0; i<len; i++) {
            if (small.markBits[i]) {
                auto live = popcnt(small.markBits[i]);
                freedLocal += 64 - live;
                usedLocal += live;
            } else {
                freedLocal += 64;
            }
            small.allocBits[i] = small.markBits[i];
        }
        small.nextFree = 0;
        freed += freedLocal;
        used += usedLocal;
    }

    void resetMarkBitsSmall() {
        small.markBits[0..(small.objects+63)/64] = 0;
    }

    // uint.max means same bits
    BlkInfo tryExtendSmall(void* p, size_t minSize, size_t maxSize, uint bits=uint.max) {
        return BlkInfo.init;
    }

    BlkInfo querySmall(void* p) {
        void* base = addrOfSmall(p);
        uint offset = cast(uint)(p - mapped.ptr) / small.objectSize;
        return BlkInfo(base, small.objectSize, attrFromNibble(small.attrs[offset], noScan));
    }
    

// LARGE POOL implementations
    uint startOfLarge(void* p) {
        uint i = cast(uint)(p - mapped.ptr) / PAGESIZE;
        return large.offsetTable[i];
    }

    void putToFreeList(uint offset, uint psize) {
        ubyte bucket = bucketOf(psize * PAGESIZE);
        large.offsetTable[offset] = large.buckets[bucket];
        large.sizeTable[offset] = psize;
        large.buckets[bucket] = offset;
    }

    BlkInfo allocateLarge(size_t size, uint bits) {
        assert(type == PoolType.LARGE);
        ubyte bucket = bucketOf(size);
        uint psize = cast(uint)(size + PAGESIZE-1) / PAGESIZE;

        BlkInfo cutOut(uint start) nothrow
        {
            for (uint i = start; i < start + psize; i++) {
                large.offsetTable[i] = start;
                large.sizeTable[i] = psize;
            }
            BlkInfo blk;
            blk.base = mapped.ptr + start*PAGESIZE;
            blk.size = psize * PAGESIZE;
            blk.attr = bits;
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

    uint getAttrLarge(void* p) {
        uint s = startOfLarge(p);
        return attrFromNibble(large.attrs[s], noScan);
    }

    uint setAttrLarge(void* p, uint attrs) {
        uint s = startOfLarge(p);
        large.attrs[s] |= attrToNibble(attrs);
        return attrFromNibble(large.attrs[s], noScan);
    }

    uint clrAttrLarge(void* p, uint attrs) {
        uint s = startOfLarge(p);
        large.attrs[s] &= cast(ubyte)~attrToNibble(attrs);
        return attrFromNibble(large.attrs[s],noScan);
    }

    size_t sizeOfLarge(void* p) {
        uint s = startOfLarge(p);
        return large.sizeTable[s];
    }

    void* addrOfLarge(void* p) {
        return mapped.ptr + startOfLarge(p)*PAGESIZE;
    }

    void[] markLarge(void* p) {
        uint start = startOfLarge(p);
        auto b = start / 8;
        uint mask = 1<<(start % 8);
        if (large.markBits[b] & mask) return null;
        uint size = large.sizeTable[start];
        for (size_t i = start; i< start + size; i++) {
            large.markBits[b] |= mask;
            mask <<= 1;
            if (mask == (1<<8)) {
                b++;
                mask = 1;
            }
        }
        if (noScan) return null;
        return mapped[start*PAGESIZE..(start+size)*PAGESIZE];
    }

    IsMarked isMarkedLarge(void *p) {
        uint start = startOfLarge(p);
        auto b = start / 8;
        uint mask = 1<<(start % 8);
        return large.markBits[b] & mask ? IsMarked.yes : IsMarked.no;
    }

    void sweepLarge(ref size_t freed, ref size_t used) {
        debug(vulture_sweep) printf("Sweeping %d pages pool\n", large.pages);
        large.buckets[] = uint.max;
        size_t pages = large.pages;
        size_t b = 0;
        uint mask = 1;
        size_t freedLocal  = 0, usedLocal = 0;
        size_t runStart = size_t.max;
        for (size_t i = 0; i < pages; i++) {
            if (!(large.markBits[b] & mask)) {
                if (runStart == size_t.max) {
                    runStart = i;
                }
            } else {
                if (runStart != size_t.max) {
                    debug(vulture_sweep) printf("Sweeped run %ld size %ld pages %ld\n", runStart, i - runStart, pages);
                    putToFreeList(cast(uint)runStart, cast(uint)(i - runStart));
                    freedLocal += (i - runStart) * PAGESIZE;
                }
                runStart = size_t.max;
                usedLocal += PAGESIZE;
            }
            mask <<=1;
            if (mask == (1<<8)) {
                mask = 1;
                b++;
            }
        }
        if (runStart != size_t.max) {
            debug(vulture_sweep) printf("Sweeped run %ld size %ld pages %ld\n", runStart, pages - runStart, pages);
            putToFreeList(cast(uint)runStart, cast(uint)(pages - runStart));
            freedLocal += (pages - runStart) * PAGESIZE;
        }
        freed += freedLocal;
        used += usedLocal;
    }

    void resetMarkBitsLarge() {
        large.markBits[0..large.pages] = 0;
    }

    // uint.max means same bits
    BlkInfo tryExtendLarge(void* p, size_t minSize, size_t maxSize, uint bits=uint.max) {
        //TODO: check if followed by free space, extend + readd it from free lists
        return BlkInfo.init;
    }

    BlkInfo queryLarge(void* p) {
        uint s = startOfLarge(p);
        void* base = mapped.ptr + s*PAGESIZE;
        size_t size = large.sizeTable[s]*PAGESIZE;
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
    BlkInfo tryExtendHuge(void* p, size_t minSize, size_t maxSize, uint bits=uint.max) {
        if (mapped.length <= maxSize) {
            auto size = maxSize;
            return BlkInfo(p, size, bits);
        } else {
            return BlkInfo.init;
        }
    }

    BlkInfo queryHuge(void* p) {
        size_t size = huge.size;
        uint attrs = getAttrHuge(p);
        return BlkInfo(mapped.ptr, size, attrs);
    }
}
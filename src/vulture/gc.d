module vulture.gc;

import core.atomic;
import core.stdc.string;
debug(vulture) import core.stdc.stdio;
static import core.memory;
import core.gc.gcinterface;
import core.gc.registry;
import core.lifetime;
import core.stdc.stdlib;
import core.sys.linux.sys.sysinfo;
import core.thread.threadbase;
import core.thread.osthread;

import vulture.memory;
import vulture.spinlock;
import vulture.pool_table;
import vulture.pool;
import vulture.size_class;
import vulture.treap;
import vulture.freelist;

alias Stats = core.memory.GC.Stats;

__gshared extern(C) void function() registrator;

extern(C) pragma(crt_constructor) void register_vulture() {
    import core.sys.posix.unistd;
    immutable s = "Registering vulture GC\n";
    write(2, s.ptr, s.length);
    registerGCFactory("vulture", &createVulture);
}

shared static this() {
    registrator = &register_vulture;
}

GC createVulture() {
    auto ptr = cast(VultureGC)calloc(1, __traits(classInstanceSize, VultureGC));
    emplace!VultureGC(ptr);
    return ptr;
}

private struct TlsCache {
    SmallAllocBatch[sizeClasses.length][2] cache;
}

class VultureGC : GC
{
    auto rootsLock = shared(AlignedSpinLock)(SpinLock.Contention.brief);
    auto rangesLock = shared(AlignedSpinLock)(SpinLock.Contention.brief);
    Treap!Root roots;
    Treap!Range ranges;
    MemoryTable memTable;       // table of pool allocations
    size_t enabled = 1;        
    bool _inFinalizer = false;
    size_t[sizeClasses.length+1][2] lastSuccessfullAlloc;
    size_t[2] numLargePools;
    static TlsCache tcache;
    shared size_t usedTotal;
    shared size_t collectThreshold;
    shared size_t maxHeapSize;
    shared size_t minHeapSize;

    this() {
        sysinfo_ info;
        sysinfo(&info);
        size_t memorySize = (info.totalram + info.totalswap) * info.mem_unit;
        debug(vulture) printf("memorySize = 0x%lx\n", memorySize);
        memTable = MemoryTable(memorySize);
        maxHeapSize = info.totalram * info.mem_unit / 4; // todo: config
        minHeapSize = maxHeapSize / 16;
        collectThreshold = minHeapSize;  // todo: config
        usedTotal = 0;
        import core.stdc.stdio;
        debug(vulture) printf("Vulture GC initialized\n");
    }

    /*
     *
     */
    void Dtor()
    {
        memTable.Dtor();
    }

    void lockAll() nothrow {
        foreach (size_t i; 0 .. memTable.length) {
            auto pool = memTable[i];
            pool.lock();
        }
    }

    void unlockAll() nothrow {
        foreach (size_t i; 0 .. memTable.length) {
            auto pool = memTable[i];
            pool.unlock();
        }
    }

    /**
     *
     */
    void enable() nothrow
    {
        atomicFetchAdd(enabled, 1);
    }

    /**
     *
     */
    void disable()
    {
        atomicFetchSub(enabled, 1);
    }

    /**
     *
     */
    void collect() nothrow {
        collectAll(false);
    }

    /**
     *
     */
    void collectNoStack() nothrow {
        collectAll(true);
    }

    void collectAll(bool noStack) nothrow {
        debug(vulture) printf("Vulture GC collect started...\n");
        thread_suspendAll();
        Pool*[] pools = cast(Pool*[])mapMemory(memTable.length * (Pool*).sizeof);
        scope(exit) unmapMemory(pools);
        size_t toSweep = 0;
        foreach (size_t i; 0 .. memTable.length){
            if (memTable[i].type != PoolType.NONE) {
                pools[toSweep++] = memTable[i];
            }
        }
        prepare();

        markAll(noStack);

        thread_processGCMarks(&isMarked);
        thread_resumeAll();

        size_t usedBefore = usedTotal;
        auto usage = sweep(pools[0..toSweep]);
        foreach (ref block; lastSuccessfullAlloc[])
        foreach (ref index; block[]) {
            atomicStore(index, 0);
        }
        usedTotal = usage.used; // update after collection
        size_t newThreshold = usage.used * 2 + (usedBefore - usage.used) / 5; // todo: config
        newThreshold = newThreshold < maxHeapSize ? newThreshold : maxHeapSize;
        newThreshold = newThreshold < minHeapSize ? minHeapSize : newThreshold;
        collectThreshold = newThreshold;
        debug(vulture) printf("Vulture GC ended");
    }

    /**
     * Returns true if the addr lies within a marked block.
     *
     * Warning! This should only be called while the world is stopped inside
     * the fullcollect function.
     */
    int isMarked(void *addr) scope nothrow {
        // first, we find the Pool this block is in, then check to see if the
        // mark bit is clear.
        auto pool = memTable.lookup(addr);
        if(pool) {
            return pool.isMarked(addr);
        }
        return IsMarked.unknown;
    }

    static struct ToScanStack {
    nothrow:
        @disable this(this);

        void reset() {
            _length = 0;
            unmapMemory(_p[0 .._cap * Range.sizeof]);
            _p = null;
            _cap = 0;
        }

        void push(Range rng) {
            if (_length == _cap) grow();
            _p[_length++] = rng;
        }

        Range pop()
        in { assert(!empty); }
        body {
            return _p[--_length];
        }

        ref inout(Range) opIndex(size_t idx) inout
        in { assert(idx < _length); }
        body {
            return _p[idx];
        }

        @property size_t length() const { return _length; }
        @property bool empty() const { return !length; }

    private:
        void grow() {
            enum initSize = 64 * 1024; // Windows VirtualAlloc granularity
            immutable ncap = _cap ? 2 * _cap : initSize / Range.sizeof;
            auto p = cast(Range*)mapMemory(ncap * Range.sizeof);
            p[0 .. _length] = _p[0 .. _length];
            unmapMemory(_p[0.._cap * Range.sizeof]);
            _p = p;
            _cap = ncap;
        }

        size_t _length;
        Range* _p;
        size_t _cap;
    }

    ToScanStack toscan;

    void mark(void *pbot, void *ptop) scope nothrow
    {
        void **p1 = cast(void **)pbot;
        void **p2 = cast(void **)ptop;

        // limit the amount of ranges added to the toscan stack
        enum FANOUT_LIMIT = 32;
        size_t stackPos;
        Range[FANOUT_LIMIT] stack = void;

    Lagain:
        // let dmd allocate registers for memory range
        const minAddr = memTable.memory.ptr;
        const maxAddr = memTable.memory.ptr + memTable.memory.length;

        //printf("marking range: [%p..%p] (%#zx)\n", p1, p2, cast(size_t)p2 - cast(size_t)p1);
    Lnext: for (; p1 < p2; p1++)
        {
            auto p = *p1;

            //if (log) debug(PRINTF) printf("\tmark %p\n", p);
            if (p >= minAddr && p < maxAddr)
            {
                Pool* pool = memTable.lookup(p);
                if (pool.type != PoolType.NONE) {
                    auto range = pool.mark(p);
                    if(range.ptr != null) {
                        stack[stackPos++] = Range(range.ptr, range.ptr + range.length);
                        if (stackPos == stack.length)
                            break;
                    }
                }
            }
        }

        Range next=void;
        if (p1 < p2)
        {
            // local stack is full, push it to the global stack
            assert(stackPos == stack.length);
            toscan.push(Range(p1, p2));
            // reverse order for depth-first-order traversal
            foreach_reverse (ref rng; stack[0 .. $ - 1])
                toscan.push(rng);
            stackPos = 0;
            next = stack[$-1];
        }
        else if (stackPos)
        {
            // pop range from local stack and recurse
            next = stack[--stackPos];
        }
        else if (!toscan.empty)
        {
            // pop range from global stack and recurse
            next = toscan.pop();
        }
        else
        {
            // nothing more to do
            return;
        }
        p1 = cast(void**)next.pbot;
        p2 = cast(void**)next.ptop;
        // printf("  pop [%p..%p] (%#zx)\n", p1, p2, cast(size_t)p2 - cast(size_t)p1);
        goto Lagain;
    }

    // stage 0 of collection
    void prepare() nothrow {
        for (size_t i = 0; i < memTable.length; i++) {
            auto pool = memTable[i];
            if (pool.type != PoolType.NONE) {
                pool.resetMarkBits();
            }
        }
    }

    void markAll(bool noStack) nothrow {
        if (!noStack)
        {
            debug(vulture) printf("Scan stacks\n");
            // Scan stacks and registers for each paused thread
            thread_scanAll(&mark);
        }

        // Scan roots[]
        debug(vulture) printf("Scan roots[]\n");
        foreach (root; roots)
        {
            mark(cast(void*)&root.proot, cast(void*)(&root.proot + 1));
        }

        // Scan ranges[]
        debug(vulture) printf("Scan ranges[]\n");
        //log++;
        foreach (range; ranges)
        {
            debug(vulture) printf("\t%p .. %p\n", range.pbot, range.ptop);
            mark(range.pbot, range.ptop);
        }
    }

    static struct MemUsage {
        size_t free;
        size_t used;
    }

    MemUsage sweep(Pool*[] pools) nothrow {
        size_t free = 0, used = 0;
        foreach (Pool* pool; pools) {
            pool.lock();
            scope(exit) pool.unlock();
            if (pool.type == PoolType.SMALL) {
                pool.sweepSmall(free, used);
            } else if (pool.type == PoolType.LARGE) {
                pool.sweepLarge(free, used);
            } else if (pool.type == PoolType.HUGE) {
                if (!pool.huge.mark) {
                    free += pool.mapped.length;
                    freeMemory(pool.mapped);
                    memTable.deallocate(pool);
                } else {
                    used += pool.mapped.length;
                }
            }
        }
        return MemUsage(free, used);
    }

    /**
     * minimize free space usage
     */
    void minimize() nothrow {
        memTable.minimize();
    }

    /**
     *
     */
    uint getAttr(void* p) nothrow {
        if (!p) return 0;
        Pool* pool = memTable.lookup(p);
        if (!pool || pool.type == PoolType.NONE) return 0;
        pool.lock();
        scope(exit) pool.unlock();
        return pool.getAttr(p);
    }

    /**
     *
     */
    uint setAttr(void* p, uint mask) nothrow {
        if (!p) return 0;
        Pool* pool = memTable.lookup(p);
        if (!pool || pool.type == PoolType.NONE) return 0;
        pool.lock();
        scope(exit) pool.unlock();
        return pool.setAttr(p, mask);
    }

    /**
     *
     */
    uint clrAttr(void* p, uint mask) nothrow {
        if (!p) return 0;
        Pool* pool = memTable.lookup(p);
        if (!pool || pool.type == PoolType.NONE) return 0;
        pool.lock();
        scope(exit) pool.unlock();
        return pool.clrAttr(p, mask);
    }

    /**
     *
     */
    void* malloc(size_t size, uint bits, const TypeInfo ti) nothrow {
        return qalloc(size, bits, ti).base;
    }

    /*
     *
     */
    BlkInfo qalloc(size_t size, uint bits, const scope TypeInfo ti) nothrow {
        // Check TypeInfo "should scan" bit
        if (ti && !(ti.flags() & 1)) bits |= BlkAttr.NO_SCAN;
        if (size <= MAXSMALL) return smallAlloc(size, bits);
        if (size <= MAXLARGE) return largeAlloc(size, bits);
        else return hugeAlloc(size, bits);
    }

    /*
     *
     */
    void* calloc(size_t size, uint bits, const TypeInfo ti) nothrow {
        return qalloc(size, bits, ti).base;
    }

    BlkInfo smallAlloc(size_t size, uint bits) nothrow {
        debug(vulture) printf("Allocating small %ld (%x)\n", size, bits);
        ubyte sclass = sizeToClass(size);
        bool noScan = (bits & BlkAttr.NO_SCAN) != 0;
        auto cache =  &tcache.cache[noScan][sclass];
        auto alloc = cache.alloc();
        debug(vulture) printf("Allocated from cache %p\n", alloc.ptr);
        if (!alloc.ptr) alloc = smallAllocSlowPath(sclass, noScan, cache);
        *alloc.attrs = attrToNibble(bits);
        return BlkInfo(alloc.ptr, size, bits); 
    }

    SmallAlloc smallAllocSlowPath(ubyte sclass, bool noScan, SmallAllocBatch* cache) nothrow {
        SmallAlloc allocateRun(Pool* pool, ref size_t allocated) {
            debug (vulture) printf("Allocating small batch\n");
            auto batch = pool.allocateSmall(allocated);
            if (batch.ptr != null) {
                *cache = batch;
                return cache.alloc();
            }
            return SmallAlloc.init;
        }
        size_t objectSize = classToSize(sclass);
        // todo: circular doubly-linked list of small pools by size class
        size_t i = 0;
        size_t candidates;
        size_t allocatedBytes = 0;
        SmallAlloc alloc;
        size_t length = memTable.length;
        for (i = atomicLoad(lastSuccessfullAlloc[noScan][sclass]); i < length; i++) {
            auto pool = memTable[i];
            if (pool.type == PoolType.SMALL && pool.small.objectSize == objectSize) {
                pool.lock();
                candidates++;
                scope(exit) pool.unlock();
                alloc = allocateRun(pool, allocatedBytes);
                if (alloc.ptr) {
                    atomicStore(lastSuccessfullAlloc[noScan][sclass], i);
                    atomicOp!"+="(usedTotal, allocatedBytes);
                    break;
                }
            }
        }
        if (i == length) {
            if (candidates >= 1 && atomicLoad(usedTotal) > collectThreshold) {
                collect();
                return smallAllocSlowPath(sclass, noScan, cache);
            }
            auto pool = memTable.allocate(CHUNKSIZE);
            pool.lock();
            debug(vulture) printf("Initializing small pool\n");
            pool.initializeSmall(sclass, noScan);
            alloc = allocateRun(pool, allocatedBytes);
            atomicOp!"+="(usedTotal, allocatedBytes);
            pool.unlock();
        }
        return alloc;
    }

    BlkInfo largeAlloc(size_t size, uint bits) nothrow {
        debug(vulture) printf("Allocating large %ld (%x)\n", size, bits);
        bool noScan = (bits & BlkAttr.NO_SCAN) != 0;
        size_t length = memTable.length;
        foreach(i; 0..length) {
            auto p = memTable[i];
            // Quick check of immutable properties w/o locking
            if (p.type == PoolType.LARGE && p.noScan == noScan) {
                p.lock();
                scope(exit) p.unlock();
                auto blk = p.allocateLarge(size, bits);
                if (blk.base) {
                    atomicOp!"+="(usedTotal, blk.size);
                    return blk;
                }
            }
        }
        if (atomicLoad(usedTotal) > collectThreshold) {
            collect();
            return largeAlloc(size, bits);
        }
        // needs meta lock for numLargePools and allocate
        auto nextSize = (++numLargePools[noScan])*16*CHUNKSIZE;
        size_t poolSize = size < nextSize ? nextSize : roundToChunk(size * 3 / 2);
        auto pool = memTable.allocate(poolSize);
        pool.lock();
        pool.initializeLarge(noScan);
        scope(exit) pool.unlock();
        auto blk = pool.allocateLarge(size, bits);
        atomicOp!"+="(usedTotal, blk.size);
        return blk;
    }

    BlkInfo hugeAlloc(size_t size, uint bits) nothrow {
        size_t allocSize = roundToChunk(size);
        if (atomicLoad(usedTotal) + allocSize > collectThreshold) {
            collect();
            return hugeAlloc(size, bits);
        }
        Pool* p = memTable.allocate(size);
        p.lock();
        p.initializeHuge(size, bits);
        p.unlock();
        atomicOp!"+="(usedTotal, allocSize);
        return BlkInfo(p.mapped.ptr, size, bits);
    }
    /*
     *
     */
    void* realloc(void* p, size_t size, uint bits, const TypeInfo ti) nothrow {
        debug(vulture) printf("GC realloc %ld\n", size);
        Pool* pool = memTable.lookup(p);
        if (!pool) return qalloc(size, bits, ti).base;
        size_t oldSize;
        {
            pool.lock();
            scope(exit) pool.unlock();
            oldSize = pool.sizeOf(p);
            BlkInfo newP = pool.tryExtend(p, size, size, bits);
            if (newP.base) return newP.base;
        }
        BlkInfo blk = qalloc(size, bits, ti);
        memcpy(blk.base, p, oldSize);
        return blk.base;
    }

    /**
     * Attempt to in-place enlarge the memory block pointed to by p by at least
     * minsize bytes, up to a maximum of maxsize additional bytes.
     * This does not attempt to move the memory block (like realloc() does).
     *
     * Returns:
     *  0 if could not extend p,
     *  total size of entire memory block if successful.
     */
    size_t extend(void* p, size_t minsize, size_t maxsize, const TypeInfo ti) nothrow {
        Pool* pool = memTable.lookup(p);
        if (!pool) return 0;
        pool.lock();
        scope(exit) pool.unlock();
        BlkInfo newP = pool.tryExtend(p, minsize, maxsize);
        return newP.size;
    }

    /**
     *
     */
    size_t reserve(size_t size) nothrow {
        return size;
    }

    /**
     *
     */
    void free(void* p) nothrow {
        Pool* pool = memTable.lookup(p);
        if (!pool) return;
        if (pool.type == PoolType.HUGE)
        {
            memTable.free(pool.mapped);
            memTable.deallocate(pool);
            return;
        }
        else if (pool.type == PoolType.SMALL) {
            // noop - todo clear allocBit
        }
        pool.lock();
        scope(exit) pool.unlock();
        return pool.freeLarge(p);
    }

    /**
     * Determine the base address of the block containing p.  If p is not a gc
     * allocated pointer, return null.
     */
    void* addrOf(void* p) nothrow {
        Pool* pool = memTable.lookup(p);
        if (!pool || pool.type == PoolType.NONE) return null;
        pool.lock();
        scope(exit) pool.unlock();
        return pool.addrOf(p);
    }

    /**
     * Determine the allocated size of pointer p.  If p is an interior pointer
     * or not a gc allocated pointer, return 0.
     */
    size_t sizeOf(void* p) nothrow
    {
        Pool* pool = memTable.lookup(p);
        if (!pool || pool.type == PoolType.NONE) return 0;
        pool.lock();
        scope(exit) pool.unlock();
        return pool.sizeOf(p);
    }

    /**
     * Determine the base address of the block containing p.  If p is not a gc
     * allocated pointer, return null.
     */
    BlkInfo query(void* p) nothrow {
        Pool* pool = memTable.lookup(p);
        if (!pool || pool.type == PoolType.NONE) return BlkInfo.init;
        pool.lock();
        scope(exit) pool.unlock();
        return pool.query(p);
    }

    /**
     * Retrieve statistics about garbage collection.
     * Useful for debugging and tuning.
     */
    Stats stats() nothrow {
        return Stats.init; // TODO: statistics
    }

    core.memory.GC.ProfileStats profileStats() @safe nothrow @nogc {
        return core.memory.GC.ProfileStats.init; // TODOL statistics
    }

    /**
     * add p to list of roots
     */
    void addRoot(void* p) nothrow @nogc {
        if(!p) return;
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        roots.insert(Root(p));
    }

    /**
     * remove p from list of roots
     */
    void removeRoot(void* p) nothrow @nogc {
        if(!p) return;
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        roots.remove(Root(p));
    }

    /**
     *
     */
    @property RootIterator rootIter() @nogc {
        return &this.rootsApply;
    }

    int rootsApply(scope int delegate(ref Root) nothrow dg) nothrow {
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        auto ret = roots.opApply(dg);
        return ret;
    }

    /**
     * add range to scan for roots
     */
    void addRange(void* p, size_t sz, const TypeInfo ti) nothrow @nogc {
        if(!p || !sz) return;
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        ranges.insert(Range(p, p+sz));
    }

    /**
     * remove range
     */
    void removeRange(void *pbot) nothrow @nogc {
        if(!pbot) return;
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        ranges.remove(Range(pbot, pbot)); // only pbot is used, see Range.opCmp
    }

    /**
     *
     */
    @property RangeIterator rangeIter() @nogc {
        return &this.rangesApply;
    }

    int rangesApply(scope int delegate(ref Range) nothrow dg) nothrow {
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        auto ret = ranges.opApply(dg);
        return ret;
    }

    ulong allocatedInCurrentThread() nothrow {
        return 0; //TODO: stats
    }

    /**
     * run finalizers
     */
    void runFinalizers(scope const(void[]) segment) nothrow {
        _inFinalizer = true;
        scope (exit) _inFinalizer = false;

        Pool* p = memTable.lookup(segment.ptr);
        if(!p || p.type == PoolType.NONE) return;
        p.runFinalizers(segment);
    }

    /*
     *
     */
    bool inFinalizer() nothrow {
        return _inFinalizer;
    }
}

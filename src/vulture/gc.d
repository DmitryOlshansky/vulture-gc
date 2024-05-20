module vulture.gc;

import core.internal.spinlock;
import core.stdc.string;
static import core.memory;
import core.gc.gcinterface;
import core.gc.registry;
import core.lifetime;
import core.stdc.stdlib;
import core.sys.linux.sys.sysinfo;

import vulture.pool_table;
import vulture.pool;
import vulture.treap;

alias Stats = core.memory.GC.Stats;

enum {
    INITIAL_POOLMAP_SIZE = 32,    
}

GC createVulture() {
    auto ptr = cast(VultureGC)calloc(1, __traits(classInstanceSize, VultureGC));
    emplace!VultureGC(ptr);
    return ptr;
}

class VultureGC : GC
{
    auto rootsLock = shared(AlignedSpinLock)(SpinLock.Contention.brief);
    auto rangesLock = shared(AlignedSpinLock)(SpinLock.Contention.brief);
    Treap!Root roots;
    Treap!Range ranges;

    // Lock around most of GC metadata including memTable
    auto metaLock = shared(SpinLock)(SpinLock.Contention.brief);
    MemoryTable memTable;
    size_t enabled = 1;
    bool _inFinalizer = false;
    size_t[2] numLargePools;

    this() {
        sysinfo_ info;
        sysinfo(&info);
        size_t memorySize = (info.totalram + info.totalswap) * PAGESIZE;
        memTable = MemoryTable(memorySize);
        import core.stdc.stdio;
        printf("Vulture GC initialized\n");
    }
    /*
     *
     */
    void Dtor()
    {
        memTable.Dtor();
    }

    /**
     *
     */
    void enable() nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        enabled++;
    }

    /**
     *
     */
    void disable()
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        enabled--;
    }

    /**
     *
     */
    void collect() nothrow
    {
        //TODO: collection ;)
    }

    /**
     *
     */
    void collectNoStack() nothrow
    {
        //TODO: collection ;)
    }

    /**
     * minimize free space usage
     */
    void minimize() nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        memTable.minimize();
    }

    /**
     *
     */
    uint getAttr(void* p) nothrow
    {
        if (!p) return 0;
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return 0;
        return pool.getAttr(p);
    }

    /**
     *
     */
    uint setAttr(void* p, uint mask) nothrow
    {
        if (!p) return 0;
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return 0;
        return pool.setAttr(p, mask);
    }

    /**
     *
     */
    uint clrAttr(void* p, uint mask) nothrow
    {
        if (!p) return 0;
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return 0;
        return pool.clrAttr(p, mask);
    }

    /**
     *
     */
    void* malloc(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        return qalloc(size, bits, ti).base;
    }

    /*
     *
     */
    BlkInfo qalloc(size_t size, uint bits, const scope TypeInfo ti) nothrow
    {
        // Check TypeInfo "should scan" bit
        if (ti && !(ti.flags() & 1)) bits |= BlkAttr.NO_SCAN;
        if (size <= MAXSMALL) return smallAlloc(size, bits);
        if(size <= MAXLARGE) return largeAlloc(size, bits);
        else return hugeAlloc(size, bits);
    }

    /*
     *
     */
    void* calloc(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        return qalloc(size, bits, ti).base;
    }

    BlkInfo qallocWithLock(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        // Check TypeInfo "should scan" bit
        if (ti && !(ti.flags() & 1)) bits |= BlkAttr.NO_SCAN;
        if (size <= MAXSMALL)
        {
            // Small alloc goes to TLS cache first so no locking upfront
            metaLock.unlock();
            return smallAlloc(size, bits);
        }
        if(size <= 8 * CHUNKSIZE) return largeAlloc(size, bits);
        else return hugeAlloc(size, bits);
    }

    BlkInfo smallAlloc(size_t size, uint bits) nothrow
    {
        ubyte sclass = sizeClassOf(size);
        return BlkInfo.init;
    }

    BlkInfo largeAlloc(size_t size, uint bits) nothrow
    {
        bool noScan = (bits & BlkAttr.NO_SCAN) != 0;
        metaLock.lock();
        foreach(i; 0..memTable.length)
        {
            auto p = memTable[i];
            // Quick check of immutable properties w/o locking
            if (p.type == PoolType.LARGE && p.noScan == noScan)
            {
                p.lock();
                if (p.large.largestFreeEstimate >= size)
                {
                    metaLock.unlock();
                    auto blk = p.allocateLarge(size, bits);
                    p.unlock();
                    if (blk.base) return blk;
                    // estimate was wrong, continue
                    metaLock.lock();
                }
            }
        }
        // TODO: maybe GC
        // needs meta lock for numLargePools
        size_t poolSize = (++numLargePools[noScan])*16*CHUNKSIZE;
        auto pool = memTable.allocate(poolSize, noScan);
        metaLock.unlock();
        return pool.allocateLarge(size, bits);
    }

    BlkInfo hugeAlloc(size_t size, uint bits) nothrow
    {
        // TODO: implement
        return BlkInfo.init;
    }
    /*
     *
     */
    void* realloc(void* p, size_t size, uint bits, const TypeInfo ti) nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return qallocWithLock(size, bits, ti).base;
        size_t oldSize;
        {
            pool.lock();
            metaLock.unlock();
            scope(exit) pool.unlock();
            oldSize = pool.sizeOf(p);
            BlkInfo newP = pool.tryExtend(p, size, size, bits);
            if (newP.base) return newP.base;
        }
        // metaLock is unlocked here
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
    size_t extend(void* p, size_t minsize, size_t maxsize, const TypeInfo ti) nothrow
    {
        metaLock.lock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return 0;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        BlkInfo newP = pool.tryExtend(p, minsize, maxsize);
        return newP.size;
    }

    /**
     *
     */
    size_t reserve(size_t size) nothrow
    {
        return size; // TODO: mmap + populate memory to be used in pools
    }

    /**
     *
     */
    void free(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return;
        if (pool.type == PoolType.HUGE)
        {
            pool.lock();
            memTable.deallocate(pool);
            pool.unlock();
            // TODO: just remove one pool
            memTable.minimize();
            return;
        }
        metaLock.unlock();
        pool.lock();
        scope(exit) pool.unlock();
        return pool.free(p);
    }

    /**
     * Determine the base address of the block containing p.  If p is not a gc
     * allocated pointer, return null.
     */
    void* addrOf(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return null;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.addrOf(p);
    }

    /**
     * Determine the allocated size of pointer p.  If p is an interior pointer
     * or not a gc allocated pointer, return 0.
     */
    size_t sizeOf(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return 0;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.sizeOf(p);
    }

    /**
     * Determine the base address of the block containing p.  If p is not a gc
     * allocated pointer, return null.
     */
    BlkInfo query(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = memTable.lookup(p);
        if (!pool) return BlkInfo.init;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.query(p);
    }

    /**
     * Retrieve statistics about garbage collection.
     * Useful for debugging and tuning.
     */
    Stats stats() nothrow
    {
        return Stats.init; // TODO: statistics
    }

    core.memory.GC.ProfileStats profileStats() @safe nothrow @nogc {
        return core.memory.GC.ProfileStats.init; // TODOL statistics
    }

    /**
     * add p to list of roots
     */
    void addRoot(void* p) nothrow @nogc
    {
        if(!p) return;
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        roots.insert(Root(p));
    }

    /**
     * remove p from list of roots
     */
    void removeRoot(void* p) nothrow @nogc
    {
        if(!p) return;
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        roots.remove(Root(p));
    }

    /**
     *
     */
    @property RootIterator rootIter() @nogc
    {
        return &this.rootsApply;
    }

    int rootsApply(scope int delegate(ref Root) nothrow dg) nothrow
    {
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        auto ret = roots.opApply(dg);
        return ret;
    }

    /**
     * add range to scan for roots
     */
    void addRange(void* p, size_t sz, const TypeInfo ti) nothrow @nogc
    {
        if(!p || !sz) return;
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        ranges.insert(Range(p, p+sz));
    }

    /**
     * remove range
     */
    void removeRange(void *pbot) nothrow @nogc
    {
        if(!pbot) return;
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        ranges.remove(Range(pbot, pbot)); // only pbot is used, see Range.opCmp
    }

    /**
     *
     */
    @property RangeIterator rangeIter() @nogc
    {
        return &this.rangesApply;
    }

    int rangesApply(scope int delegate(ref Range) nothrow dg) nothrow
    {
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
    void runFinalizers(scope const(void[]) segment) nothrow
    {
        metaLock.lock();
        _inFinalizer = true;
        scope (exit)
        {
            _inFinalizer = false;
            metaLock.unlock();
        }

        Pool* p = memTable.lookup(segment.ptr);
        if(!p) return;
        p.runFinalizers(segment);
    }

    /*
     *
     */
    bool inFinalizer() nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        return _inFinalizer;
    }
}

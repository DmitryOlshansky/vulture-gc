/*
    Vulture GC's pool table implementaiton.
    Is a major part of GC metadata maintains a mapping
    from 2MB memory chunks to GC's pools.
*/
module vulture.pool_table;

import vulture.pool, vulture.memory;

import core.atomic;
import core.stdc.stdlib;
debug(vulture) import core.stdc.stdio;

nothrow @nogc:

size_t roundToChunk(size_t size) {
    return (size + CHUNKSIZE - 1) & ~(CHUNKSIZE - 1);
}

struct MemoryTable
{
nothrow @nogc:
    this(size_t heapSize) {
        auto size = heapSize*8;
        memory = mapMemory(size);
        memoryEnd = memory.ptr + memory.length;
        auto range = mapMemory(heapSize / CHUNKSIZE * Pool.sizeof);
        pools = (cast(Pool*)range.ptr)[0 .. range.length / Pool.sizeof];
        auto poolMapRange = mapMemory(size / CHUNKSIZE * (void*).sizeof);
        poolMap = (cast(Pool**)poolMapRange.ptr)[0 .. poolMapRange.length / (void*).sizeof];
        memoryNextFree = 0;
        nextFreePool = 0;
    }

    // allocate an uninitialized pool object
    Pool* allocate(size_t size) {
        auto _size = roundToChunk(size);
        auto nchunks = _size / CHUNKSIZE;        
        Pool* pool = atomicLoad(freelist);
        while (pool != null) {
            auto next = freelist.next;
            if(cas(&freelist, pool, next)) break;
            pool = atomicLoad(freelist);
        }
        if (pool == null) {
            pool = &pools[atomicFetchAdd(nextFreePool, 1)];
        }
        pool.next = null;
        auto start = findMemoryRange(nchunks);
        foreach (i; start .. start + nchunks) {
            poolMap[i] = pool;
        }
        debug(vulture) printf("Memory range %ld\n", start);
        auto arena = memory[start*CHUNKSIZE .. (start+nchunks)*CHUNKSIZE];
        debug(vulture) printf("Pool allocated %p..%p\n", arena.ptr, arena.ptr + arena.length);
        pool.type = PoolType.NONE;
        pool.mapped = arena;
        return pool;
    }

    void deallocate(Pool* pool) {
        size_t start = (pool.mapped.ptr - memory.ptr) / CHUNKSIZE;
        size_t end = start + pool.mapped.length / CHUNKSIZE;
        foreach (i; start .. end) {
            poolMap[i] = null;
        }
        pool.type = PoolType.NONE;
        do {
            pool.next = atomicLoad(freelist);
        } while(!cas(&freelist, pool.next, pool));
    }

    void free(void[] mapping) {
        freeMemory(mapping);
    }

    Pool* opIndex(size_t idx) { return pools.ptr + idx; }

    size_t length() { return nextFreePool; }

    // find memory range in CHUNKSIZE increments
    private size_t findMemoryRange(size_t nchunks) {
        auto start = memoryNextFree;
        auto end = (memoryEnd - memory.ptr) / CHUNKSIZE;
        foreach (i; start .. end - nchunks) {
            size_t j = i;
            for (j=i; j < i + nchunks; j++) {
                if (poolMap[j] != null) break;
            }
            if (j == i + nchunks) {
                auto cur = atomicLoad(memoryNextFree);
                if (cur <= i && cas(&memoryNextFree, cur, j)) {
                    return i;
                }
            }
        }
        foreach (i; 0 .. start - nchunks) {
            size_t j = i;
            for (j=i; j < i + nchunks; j++) {
                if (poolMap[j] != null) break;
            }
            if (j == i + nchunks) {
                auto cur = atomicLoad(memoryNextFree);
                if (cur <= i && cas(&memoryNextFree, cur, j)) {
                    return i;
                }
            }
        }
        assert(0, "Memory fragmentation is too high");
    }

    // Lookup pool for a given pointer, null is not in GC heap or unallocated
    Pool* lookup(const void *p) {
        if (p >= memory.ptr && p < memoryEnd) {
            auto offset = p - memory.ptr;
            return poolMap[offset / CHUNKSIZE];
        }
        return null;
    }

    void minimize() {
        
    }

    void Dtor() {
        unmapMemory(memory);
        unmapMemory(poolMap);
        unmapMemory(pools);
    }

    void[] memory;
    void* memoryEnd;
    Pool[] pools;
    Pool*[] poolMap;
    Pool* freelist;
    size_t nextFreePool;    // in Pool.sizeof increments 
    size_t memoryNextFree;  // in CHUNKSIZE increments
}

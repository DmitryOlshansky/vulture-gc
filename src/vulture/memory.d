module vulture.memory;

import core.sys.linux.sys.mman;
import core.stdc.stdlib;
import core.stdc.stdio;

enum {
    PAGESIZE = 4096,
    MADV_FREE = 8
}

@nogc nothrow:

void[] mapMemory(size_t size) {
    auto roundedSize = (size + PAGESIZE - 1) & ~(PAGESIZE - 1);
    debug(vulture) printf("Mapped %ld bytes %ld pages\n", roundedSize, roundedSize / PAGESIZE);
    auto mem = mmap(null, roundedSize, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == cast(void*)-1) {
        perror("unable to mmap");
        abort();
    }
    return mem[0..roundedSize];
}

void freeMemory(void[] slice) {
    auto ret = madvise(slice.ptr, slice.length, MADV_DONTNEED);
    if (ret < 0) {
        perror("unable to free mmap area");
        abort();
    }
}

void unmapMemory(void[] slice) {
    munmap(slice.ptr, slice.length);
}

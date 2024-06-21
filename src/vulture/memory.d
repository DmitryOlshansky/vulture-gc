module vulture.memory;

version(linux) {
    import core.sys.linux.sys.mman;
} else version (OSX) {
    import core.sys.darwin.sys.mman;
    import core.sys.darwin.mach.kern_return;
    import core.sys.darwin.mach.port;
    import core.sys.darwin.sys.sysctl;
    
    
    
    enum CTL_HW = 6;
    enum HW_PAGESIZE = 7;

    struct vm_statistics {
        natural_t       free_count;             /* # of pages free */
        natural_t       active_count;           /* # of pages active */
        natural_t       inactive_count;         /* # of pages inactive */
        natural_t       wire_count;             /* # of pages wired down */
        natural_t       zero_fill_count;        /* # of zero fill pages */
        natural_t       reactivations;          /* # of pages reactivated */
        natural_t       pageins;                /* # of pageins */
        natural_t       pageouts;               /* # of pageouts */
        natural_t       faults;                 /* # of faults */
        natural_t       cow_faults;             /* # of copy-on-writes */
        natural_t       lookups;                /* object cache lookups */
        natural_t       hits;                   /* object cache hits */

        /* added for rev1 */
        natural_t       purgeable_count;        /* # of pages purgeable */
        natural_t       purges;                 /* # of pages purged */

        /* added for rev2 */
        /*
        * NB: speculative pages are already accounted for in "free_count",
        * so "speculative_count" is the number of "free" pages that are
        * used to hold data that was read speculatively from disk but
        * haven't actually been used by anyone so far.
        */
        natural_t       speculative_count;      /* # of pages speculative */
    }

    enum HOST_VM_INFO_COUNT = vm_statistics.sizeof / natural_t.sizeof;
    enum HOST_VM_INFO = 2;
    extern(C) mach_port_t mach_host_self();

    alias host_t = mach_port_t;
    alias host_flavor_t = int;
    alias host_info_t = int*;
    alias mach_msg_type_number_t = natural_t;

    extern(C) kern_return_t host_statistics(
	    host_t host_priv,
	    host_flavor_t flavor,
	    host_info_t host_info_out,
	    mach_msg_type_number_t* host_info_outCnt
);
} else {
    static assert(0, "Unsupported OS");
}
import core.stdc.stdlib;
import core.stdc.stdio;

immutable size_t PAGESIZE;
immutable size_t TOTAL_MEMORY;

shared static this() {
    version(linux) {
        PAGESIZE = 4096;
        sysinfo_ info;
        sysinfo(&info);
        TOTAL_MEMORY = (info.totalram + info.totalswap) * info.mem_unit;

    } else version(OSX) {
        int[6] mib; 
        mib[0] = CTL_HW;
        mib[1] = HW_PAGESIZE;

        int pagesize;
        size_t length;
        length = pagesize.sizeof;
        if (sysctl (mib.ptr, 2, &pagesize, &length, null, 0) < 0) {
            perror("cannot get page size");
            abort();
        }
        PAGESIZE = pagesize;
        uint count = HOST_VM_INFO_COUNT;
        vm_statistics vmstat;
        if (host_statistics (mach_host_self(), HOST_VM_INFO, cast(host_info_t) &vmstat, &count) != KERN_SUCCESS) {
            perror("cannot get host statistics");
            abort();
        }
        TOTAL_MEMORY = PAGESIZE * (vmstat.wire_count + vmstat.active_count + vmstat.inactive_count + vmstat.free_count);
    } else {
        static assert(0, "Unsupported OS");
    }
}

@nogc nothrow:

void[] mapMemory(size_t size) {
    auto roundedSize = (size + PAGESIZE - 1) & ~(PAGESIZE - 1);
    debug(vulture) printf("Mapped %ld bytes %ld pages\n", roundedSize, roundedSize / PAGESIZE);
    auto mem = mmap(null, roundedSize, PROT_READ | PROT_WRITE, MAP_NORESERVE | MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == cast(void*)-1) {
        perror("unable to mmap");
        abort();
    }
    return mem[0..roundedSize];
}

void freeMemory(void[] slice) {
    version(linux) {
        auto ret = madvise(slice.ptr, slice.length, MADV_DONTNEED);
    } else version(OSX) {
        auto ret = madvise(slice.ptr, slice.length, MADV_FREE_REUSABLE);
    } else {
        static assert(0, "Unsupported OS");
    }
    if (ret < 0) {
        perror("unable to free mmap area");
        abort();
    }
}

void unmapMemory(void[] slice) {
    munmap(slice.ptr, slice.length);
}

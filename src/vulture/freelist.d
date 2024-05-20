module vulture.freelist;

import core.atomic;


unittest {
    static struct Entry {
        Entry* next;
        int id;        
    }
    import std.range, std.algorithm;
    auto entries = iota(0, 10).map!(x => Entry(null, x)).array;
    FreeList list;
    foreach (ref e; entries)
        list.push(&e);
    auto popped = iota(0, 10).map!(_ => *cast(Entry*)list.pop()).array.reverse.array;
    assert(equal(entries.map!(x => x.id), popped.map!(x => x.id)));
    assert(list.pop() == null);
    foreach (i, ref e; entries[0..5]) {
        if (i != 4) {
            e.next =  &entries[i+1];
        }
        else {
            e.next = null;
        }
    }
    list.push(&entries[0], &entries[4]);
    foreach (i, ref e; entries[5..10]) {
        if (i != 4) {
            e.next =  &entries[5+i+1];
        }
        else {
            e.next = null;
        }
    }
    list.push(&entries[5], &entries[9]);
    auto twoHalfs = iota(0, 10).map!(_ => (cast(Entry*)list.pop()).id).array;
    assert(twoHalfs == [5, 6, 7, 8, 9, 0, 1, 2, 3, 4]);
}

nothrow @nogc:

struct FreeList {
    nothrow @nogc:
    
    void push(void* mem) {
        void* old;
        do {
            old = head;
            nextOf(mem) = old;
        } while(!cas(&head, old, mem));
    }

    void push(void* start, void* end) {
        void* old;
        do {
            old = head;
            nextOf(end) = old;
        } while(!cas(&head, old, start));
    }

    // null if empty
    void* pop() {
        void* it, next;
        do {
            it = head;
            if (it == null) return null;
            next = nextOf(it);
        } while (!cas(&head, it, next));
        return it;
    }
private:
    void* head;
}

ref void* nextOf(void* ptr) {
    return *cast(void**)ptr;
}

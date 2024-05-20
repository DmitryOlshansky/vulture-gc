module vulture.freelist;

import core.atomic;


struct FreeList {
    nothrow @nogc:
    
    void push(void* mem) {
        void* old;
        do {
            old = head;
            nextOf(mem) = old;
        } while(!cas(&head, old, mem));
    }

    // null if empty
    void* pop() {
        void* it, next;
        do {
            it = head;
            next = nextOf(it);
        } while (!cas(&head, it, next));
        return it;
    }
private:
    void* head;
    static ref void* nextOf(void* ptr) {
        return *cast(void**)ptr;
    }
}
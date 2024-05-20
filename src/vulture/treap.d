/**
 * Copied from DRtunime
 * Treap container for internal usage.
 *
 * Copyright: Copyright Digital Mars 2014 - 2014.
 * License:   $(WEB www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
 */
module vulture.treap;

import core.stdc.stdlib;

struct Rand48
{
    private ulong rng_state;

@safe @nogc nothrow:

    void defaultSeed()
    {
        import ctime = core.stdc.time : time;
        seed(cast(uint)ctime.time(null));
    }

pure:

    void seed(uint seedval)
    {
        assert(seedval);
        rng_state = cast(ulong)seedval << 16 | 0x330e;
        popFront();
    }

    auto opCall()
    {
        auto result = front;
        popFront();
        return result;
    }

    @property uint front()
    {
        return cast(uint)(rng_state >> 16);
    }

    void popFront()
    {
        immutable ulong a = 25214903917;
        immutable ulong c = 11;
        immutable ulong m_mask = (1uL << 48uL) - 1;
        rng_state = (a*rng_state+c) & m_mask;
    }

    enum empty = false;
}

struct Treap(E)
{
nothrow:
    static struct Node
    {
        Node* left, right;
        E element;
        uint priority;
    }

    @disable this(this);

    ~this()
    {
        removeAll();
    }

    void initialize()
    {
        rand48.defaultSeed();
    }

    void insert(E element) @nogc
    {
        root = insert(root, element);
    }

    void remove(E element)
    {
        remove(&root, element);
    }

    int opApply(scope int delegate(ref E) nothrow dg)
    {
        return (cast(const)&this).opApply((ref const E e) => dg(*cast(E*)&e));
    }

    int opApply(scope int delegate(ref const E) nothrow dg) const
    {
        return opApplyHelper(root, dg);
    }

    version(unittest)
    bool opEquals(E[] elements)
    {
        size_t i;
        foreach (e; this)
        {
            if (i >= elements.length)
                return false;
            if (e != elements[i++])
                return false;
        }
        return i == elements.length;
    }

    void removeAll()
    {
        removeAll(root);
        root = null;
    }

    version(none)
    uint height()
    {
        static uint height(Node* node)
        {
            if (!node)
                return 0;
            auto left = height(node.left);
            auto right = height(node.right);
            return 1 + (left > right ? left : right);
        }
        return height(root);
    }

    version(none)
    size_t count()
    {
        static size_t count(Node* node)
        {
            if (!node)
                return 0;
            return count(node.left) + count(node.right) + 1;
        }
        return count(root);
    }


private:
    Node* root;
    Rand48 rand48;

    Node* allocNode(E element) @nogc
    {
        Node* node = cast(Node*)malloc(Node.sizeof);
        node.left = node.right = null;
        node.priority = rand48();
        node.element = element;
        return node;
    }

    Node* insert(Node* node, E element) @nogc
    {
        if (!node)
            return allocNode(element);
        else if (element < node.element)
        {
            node.left = insert(node.left, element);
            if (node.left.priority < node.priority)
                node = rotateR(node);
        }
        else if (element > node.element)
        {
            node.right = insert(node.right, element);
            if (node.right.priority < node.priority)
                node = rotateL(node);
        }
        else
        {} // ignore duplicate

        return node;
    }

static:

    void freeNode(Node* node)
    {
        free(node);
    }

    Node* rotateL(Node* root)
    {
        auto pivot = root.right;
        root.right = pivot.left;
        pivot.left = root;
        return pivot;
    }

    Node* rotateR(Node* root)
    {
        auto pivot = root.left;
        root.left = pivot.right;
        pivot.right = root;
        return pivot;
    }

    void remove(Node** ppnode, E element)
    {
        Node* node = *ppnode;
        if (!node)
            return; // element not in treap

        if (element < node.element)
        {
            remove(&node.left, element);
        }
        else if (element > node.element)
        {
            remove(&node.right, element);
        }
        else
        {
            while (node.left && node.right)
            {
                if (node.left.priority < node.right.priority)
                {
                    *ppnode = rotateR(node);
                    ppnode = &(*ppnode).right;
                }
                else
                {
                    *ppnode = rotateL(node);
                    ppnode = &(*ppnode).left;
                }
            }
            if (!node.left)
                *ppnode = node.right;
            else
                *ppnode = node.left;
            freeNode(node);
        }
    }

    void removeAll(Node* node)
    {
        if (!node)
            return;
        removeAll(node.left);
        removeAll(node.right);
        freeNode(node);
    }

    int opApplyHelper(const Node* node, scope int delegate(ref const E) nothrow dg)
    {
        if (!node)
            return 0;

        int result = opApplyHelper(node.left, dg);
        if (result)
            return result;
        result = dg(node.element);
        if (result)
            return result;
        return opApplyHelper(node.right, dg);
    }
}
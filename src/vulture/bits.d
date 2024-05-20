module vulture.bits;

struct BitArray
{
nothrow @nogc:
    ubyte opIndex(size_t i)
    {
        return 0;
    }

    ubyte opIndexAssign(ubyte v, size_t i)
    {
        return 0;
    }

    void opSliceAssign(ubyte v, size_t s, size_t e)
    {

    }

    uint scan32(uint start)
    {
        return 0;
    }

    uint read32(uint offset)
    in
    {
        assert(offset % 32 == 0);
    }
    body
    {
        return 0;
    }

    void write32(uint val, uint offset)
    in
    {
        assert(offset % 32 == 0);
    }
    body
    {
        
    }
}

struct NibbleArray
{
nothrow @nogc:
    ubyte opIndex(size_t i)
    {
        return 0;
    }

    ubyte opIndexAssign(ubyte v, size_t i)
    {
        return 0;
    }

    ubyte opIndexOpAssign(string op)(ubyte v, size_t i)
    if(op == "|" || op == "&")
    {
        return 0;
    }

    void opSliceAssign(ubyte v, size_t s, size_t e)
    {

    }
}

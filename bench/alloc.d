/+ dub.json:
    {
	"copyright": "Copyright © 2024, Dmitry Olshansky",
	"dependencies": {
		"vulture-gc": { "path": ".." }
	},
	"description": "GC allocation throughput test",
	"name": "alloc"
}
+/
module bench.alloc;

import core.memory;
import std.conv, std.stdio;
import vulture.gc;

class ObjectTestBase { ObjectTestBase next;}
class ObjectTestSmall : ObjectTestBase {  }
class ObjectTestLarge : ObjectTestBase { ubyte[4096] data; }
class ObjectTestHuge : ObjectTestBase { ubyte[16*(1<<20)] data; }

int main(string[] argv) {
    ObjectTestBase function() alloc;
    size_t objectsChain = 0;
    if (argv.length == 1) {
        writeln("Pass one of [small, large, huge] as the first argument");
        return 1;
    }
    switch (argv[1]) {
        case "small":
            alloc = () {
                return cast(ObjectTestSmall)GC.malloc(__traits(classInstanceSize, ObjectTestSmall)); 
            };
            objectsChain = 100_000;
            break;
        case "large":
            alloc = () { 
                return cast(ObjectTestLarge)GC.malloc(__traits(classInstanceSize, ObjectTestLarge)); 
            };
            objectsChain = 10_000;
            break;
        case "huge":
            alloc = () {
                return cast(ObjectTestHuge)GC.malloc(__traits(classInstanceSize, ObjectTestHuge)); 
            };
            objectsChain = 10;
            break;
        default:
            writeln("Pass one of [small, large, huge] as the first argument");
            return 1;

    }
    for (uint k = 0; k < 50; k++) {
        GC.disable();
        for (uint i = 0; i < 20; i++) {
            auto root = alloc();
            for (uint j = 0; j < objectsChain; j++) {
                root.next = alloc();
                root = root.next;
            }
        }
        GC.collect();
    }
    return 0;
}
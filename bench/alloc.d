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

import core.memory, core.thread;
import std.conv, std.stdio;
import vulture.gc;

class ObjectTestBase { ObjectTestBase next;}
class ObjectTestSmall : ObjectTestBase {  }
class ObjectTestLarge : ObjectTestBase { ubyte[4096] data; }
class ObjectTestHuge : ObjectTestBase { ubyte[16*(1<<20)] data; }

int main(string[] argv) {
    ObjectTestBase function() alloc;
    size_t objectsChain = 0;
    if (argv.length != 3) {
        writeln("Usage: ./alloc (small|large|huge) <n>");
        writeln("Pass one of [small, large, huge] as the first argument and thread count as the second argument");
        return 1;
    }
    switch (argv[1]) {
        case "small":
            alloc = () {
                return new ObjectTestSmall; 
            };
            objectsChain = 100_000;
            break;
        case "large":
            alloc = () { 
                return new ObjectTestLarge; 
            };
            objectsChain = 10_000;
            break;
        case "huge":
            alloc = () {
                return new ObjectTestHuge; 
            };
            objectsChain = 10;
            break;
        default:
            writeln("Pass one of [small, large, huge] as the first argument");
            return 1;
    }
    size_t numThreads = argv[2].to!int;
    Thread[] threads = new Thread[numThreads];
    foreach (ref t; threads){
        t = new Thread({
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
        });
        t.start();   
    }
    foreach (ref t; threads){
        t.join();
    }
    return 0;
}
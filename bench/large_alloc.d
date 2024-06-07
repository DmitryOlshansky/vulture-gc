/+ dub.json:
    {
	"copyright": "Copyright © 2024, Dmitry Olshansky",
	"dependencies": {
		"vulture-gc": { "path": ".." }
	},
	"description": "GC large allocation",
	"name": "large_alloc"
}
+/
module bench.large_alloc;

import core.memory;
import vulture.gc;

class ObjectTest { ubyte[4096] store; ObjectTest next; }
void main() {
    for (uint k = 0; k < 50; k++) {
        GC.disable();
        for (uint i = 0; i < 20; i++) {
            auto root = new ObjectTest();
            for (uint j = 0; j < 10_000; j++) {
                root.next = new ObjectTest();
                root = root.next;
            }
        }
        GC.collect();
    }
}
/+ dub.json:
    {
	"copyright": "Copyright © 2024, Dmitry Olshansky",
	"dependencies": {
		"vulture-gc": { "path": ".." }
	},
	"description": "Simple GC test",
	"name": "simple"
}
+/
module bench.simple;

import core.memory;
import vulture.gc;

class ObjectTest { ObjectTest next; }
void main() {
    for (uint k = 0; k < 50; k++) {
        GC.disable();
        for (uint i = 0; i < 20; i++) {
            auto root = new ObjectTest();
            for (uint j = 0; j < 100_000; j++) {
                root.next = new ObjectTest();
                root = root.next;
            }
        }
        GC.collect();
    }
}
/+ dub.json:
    {
	"authors": [
		"Dmitry Olshansky"
	],
	"copyright": "Copyright © 2024, Dmitry Olshansky",
	"dependencies": {
		"vulture-gc": { "path": ".." }
	},
	"debugVersions": ["vulture"],
	"description": "A test for vulture GC registration",
	"license": "BOOST",
	"name": "hello"
}
+/
module tests.hello;

import vulture.gc;
import core.gc.registry;


void main() {
    new int[4];
	new ubyte[2048];
	new ubyte[32<<20];
}
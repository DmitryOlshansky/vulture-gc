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

import core.stdc.stdio;

void main() {
    auto arr = new int[4];
	foreach (i; 0 .. 1000)
	{
		arr ~= i; 
	}
	printf("Arr[$-1] = %d\n", arr[$-1]);
	new ubyte[2048];
	auto huge = new ubyte[32<<20];
	huge.length *= 2;
}
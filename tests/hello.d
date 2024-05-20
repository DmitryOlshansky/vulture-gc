/+ dub.json:
    {
	"authors": [
		"Dmitry Olshansky"
	],
	"copyright": "Copyright © 2024, Dmitry Olshansky",
	"dependencies": {
		"vulture-gc": { "path": ".." }
	},
	"description": "A test for vulture GC registration",
	"license": "BOOST",
	"name": "hello"
}
+/
module tests.hello;

import vulture.gc;
import core.gc.registry;


extern(C) pragma(crt_constructor) void register_vulture() {
    import core.sys.posix.unistd;
    write(2, s.ptr, s.length);
    registerGCFactory("vulture", &createVulture);
}

void main() {
    new int[4];
}
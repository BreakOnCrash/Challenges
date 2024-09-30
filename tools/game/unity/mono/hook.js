// https://tomorrowisnew.com/posts/Hacking-Mono-Games-With-Frida/
// https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/
// http://blog.sycsec.com/2019/01/07/Injecting-code-into-C-Sharp-game-scripts-via-Mono/

/*
$ frida "Game name" -l hook.js
> hook('', 'Umbrella', 'get_CurrentDurability', {
    onEnter(args) {
        console.log("Arg[0]: " + args[0].toString());
    },
	onLeave: function (retval) {
        console.log("Return value: " + retval);
	}
})

*/

const MonoMainAssembly = "Assembly-CSharp";

var MonoModuleName;
if (Process.platform === 'darwin' || Process.platform === 'ios') {
    MonoModuleName = "libmonobdwgc-2.0.dylib";
} else if (Process.platform === 'win32') {
    MonoModuleName = "mono-2.0-bdwgc.dll";
} else if (Process.platform === 'linux' || Process.platform === 'android') {
    MonoModuleName = "libmonosgen-2.0.so";
}


var Mono = Process.getModuleByName(MonoModuleName);
let MonoApi = {
    mono_get_root_domain: ['pointer', []],
    mono_thread_attach: ['pointer', ['pointer']],

    mono_assembly_foreach: ['void', ['pointer', 'pointer']],
    mono_assembly_get_image: ['pointer', ['pointer']],
    mono_image_get_name: ['pointer', ['pointer']],

    mono_class_from_name: ['pointer', ['pointer', 'pointer', 'pointer']],
    mono_class_get_method_from_name: ['pointer', ['pointer', 'pointer', 'int']],
    mono_compile_method: ['pointer', ['pointer']],
}

Object.keys(MonoApi).forEach(exportName => {
    const signature = MonoApi[exportName];
    if (signature !== null) {
        const addr = Mono.getExportByName(exportName);
        if (addr) {
            MonoApi[exportName] = new NativeFunction(addr, ...signature);
        } else {
            console.log("Could not find export: " + exportName);
        }
    }
});


var AssemblyCSharpImage;
var findMainImage = new NativeCallback(function (assembly, userData) {
    var image = MonoApi.mono_assembly_get_image(assembly);
    if (image.isNull()) {
        return;
    }

    if (MonoApi.mono_image_get_name(image).readUtf8String() == MonoMainAssembly) {
        console.log("AssemblyCsharp Found. Assembly object at :" + image);
        AssemblyCSharpImage = image;
        return;
    }
}, 'void', ['pointer', 'pointer']);

let DEBUG = true;
function hook(namespace, className, methodName, callbacks) {
    if (AssemblyCSharpImage != null) {
        var klass = MonoApi.mono_class_from_name(ptr(AssemblyCSharpImage),
            Memory.allocUtf8String(namespace),
            Memory.allocUtf8String(className));

        if (klass != 0x0) {
            if (DEBUG) console.log("Found class: " + className)

            var method = MonoApi.mono_class_get_method_from_name(klass,
                Memory.allocUtf8String(methodName), -1);

            if (method != 0x0) {
                if (DEBUG) console.log("Found method: " + methodName)

                var impl = MonoApi.mono_compile_method(method);
                Interceptor.attach(impl, { ...callbacks })
            }
        }
    }
}


MonoApi.mono_thread_attach(MonoApi.mono_get_root_domain())
MonoApi.mono_assembly_foreach(findMainImage, ptr(0));

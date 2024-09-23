// https://tomorrowisnew.com/posts/Hacking-Mono-Games-With-Frida/
// https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/

const MonoMainAssembly = "Assembly-CSharp";

var MonoModuleName;
if (Process.platform === 'darwin' || Process.platform === 'ios') {
    MonoModuleName = "libmonobdwgc-2.0.dylib";
} else if (Process.platform === 'win32') {
    MonoModuleName = "mono-2.0-bdwgc.dll";
} else if (Process.platform === 'linux' || Process.platform === 'android') {
    MonoModuleName = "libmonosgen-2.0.so";
}


var Mono = Process.getModuleByName(MonoMoudleName);
let MonoApi = {
    mono_get_root_domain: ['pointer'],
    mono_thread_attach: ['pointer', ['pointer']],

    mono_assembly_foreach: ['void', ['pointer', 'pointer']],

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
        AssemblyCSharp = image;
        return;
    }
}, 'void', ['pointer', 'pointer']);

function hook(className, methodName, paramsCount, callbacks) {
    if (AssemblyCSharpImage != null) {
        var klass = MonoApi.mono_class_from_name(ptr(AssemblyCsharpAssembly), Memory.allocUtf8String(""), Memory.allocUtf8String(className));
        if (!klass) {
            return;
        }

        var method = MonoApi.mono_class_get_method_from_name(klass, Memory.allocUtf8String(methodName), paramsCount);
        if (method){
            var impl = MonoApi.mono_compile_method(method);
            Interceptor.attach(impl, {...callbacks})
        }
    }
}


MonoApi.mono_thread_attach(MonoApi.mono_get_root_domain())
MonoApi.mono_assembly_foreach(findMainImage, ptr(0));

// TODO
hook('', '', 3, {
    onEnter(args) {
        // TODO
        for (var i = 0; i < 3; i++) {
            console.log("Arg[" + i + "]: " + args[i].toString());
        }
    },
    onLeave: function (retval) {
        console.log("Return value: " + retval);
    }
})
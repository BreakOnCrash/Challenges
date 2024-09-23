// https://tomorrowisnew.com/posts/Hacking-Mono-Games-With-Frida/

var MonoMainAssembly = "Assembly-CSharp";
var MonoMoudleName = "libmonobdwgc-2.0.dylib";  // darwin
//                   "mono-2.0-bdwgc.dll";      // windows

var Mono = Process.getModuleByName(MonoMoudleName);

var mono_get_root_domain = new NativeFunction(Mono.getExportByName("mono_get_root_domain"), 'pointer', []);
var mono_thread_attach = new NativeFunction(Mono.getExportByName("mono_thread_attach"), 'pointer', ['pointer']);
var mono_assembly_foreach = new NativeFunction(Mono.getExportByName("mono_assembly_foreach"), 'void', ['pointer', 'pointer']);

var mono_class_from_name = new NativeFunction(Mono.getExportByName("mono_class_from_name"), 'pointer', ['pointer', 'pointer', 'pointer'])
var mono_class_get_method_from_name = new NativeFunction(Mono.getExportByName("mono_class_get_method_from_name"), 'pointer', ['pointer', 'pointer', 'int'])
var mono_compile_method = new NativeFunction(Mono.getExportByName("mono_compile_method"), 'pointer', ['pointer'])

var AssemblyCSharpImage;

var findMainImage = new NativeCallback(function (assembly, userData) {
    var image = mono_assembly_get_image(assembly);
    if (image.isNull()) {
        return;
    }

    if (mono_image_get_name(image).readUtf8String() == MonoMainAssembly) {
        console.log("AssemblyCsharp Found. Assembly object at :" + image);
        AssemblyCSharp = image;
        return;
    }
}, 'void', ['pointer', 'pointer']);

function hookfunc(className, methodName, paramsCount) {
    if (AssemblyCSharpImage != null) {
        var klass = mono_class_from_name(ptr(AssemblyCsharpAssembly), Memory.allocUtf8String(""), Memory.allocUtf8String(className));
        var method = mono_class_get_method_from_name(klass, Memory.allocUtf8String(methodName), paramsCount);
        var methodCompiled = mono_compile_method(method);

        Interceptor.attach(methodCompiled, {
            onEnter(args) {
                // TODO
                for (var i = 0; i < paramsCount; i++) {
                    console.log("Arg[" + i + "]: " + args[i].toString());
                }
            },
            onLeave: function (retval) {
                console.log("Return value: " + retval);
            }
        });
    }
}


mono_thread_attach(mono_get_root_domain());
mono_assembly_foreach(findMainImage, ptr(0));

// TODO
hookfunc("", "", 1)
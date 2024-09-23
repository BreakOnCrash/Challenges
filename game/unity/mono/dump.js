// This code references the following source:
// MonoDumper - GrannyConsole.cpp
// URL: https://github.com/xia0ji233/MonoDumper/blob/master/GrannyConsole/GrannyConsole.cpp
// Author: xia0ji233

const MONO_TABLE_TYPEDEF = 2;
const MONO_TOKEN_TYPE_DEF = 0x02000000;

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
    mono_image_get_table_info: ['pointer', ['pointer', 'int']],

    mono_type_get_name: ['pointer', ['pointer']],
    mono_table_info_get_rows: ['int', ['pointer']],

    mono_class_get: ['pointer', ['pointer', 'int']],
    mono_class_get_name: ['pointer', ['pointer']],
    mono_class_from_mono_type: ['pointer', ['pointer']],
    mono_class_get_methods: ['pointer', ['pointer', 'pointer']],
    mono_class_get_fields: ['pointer', ['pointer', 'pointer']],

    mono_field_get_type: ['pointer', ['pointer']],
    mono_field_get_name: ['pointer', ['pointer']],

    mono_method_get_name: ['pointer', ['pointer']],
    mono_method_get_param_names: ['void', ['pointer', 'pointer']],

    mono_method_signature: ['pointer', ['pointer']],
    mono_signature_get_return_type: ['pointer', ['pointer']],
    mono_signature_get_param_count: ['int', ['pointer']],
    mono_signature_get_params: ['pointer', ['pointer', 'pointer']],
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

var dumpAllClass = new NativeCallback(function (assembly, userData) {
    var image = MonoApi.mono_assembly_get_image(assembly);
    if (image.isNull()) {
        console.log("Image is null for assembly");
        return;
    }

    if (MonoApi.mono_image_get_name(image).readUtf8String() == MonoMainAssembly) {
        console.log("AssemblyCsharp Found. Assembly object at :" + image);

        // list class
        var table = MonoApi.mono_image_get_table_info(image, MONO_TABLE_TYPEDEF);
        var rows = MonoApi.mono_table_info_get_rows(table);
        console.log("Number of classes in Assembly-CSharp: " + rows);
        // Iterate over all the classes
        for (var i = 0; i < rows; i++) {
            var klass = MonoApi.mono_class_get(image, MONO_TOKEN_TYPE_DEF | (i + 1));
            if (!klass.isNull()) {
                var className = Memory.readUtf8String(MonoApi.mono_class_get_name(klass));
                console.log("Class " + ": " + className);

                // list fields
                var iter = Memory.alloc(Process.pointerSize);
                var field;
                // Iterate over all the fields
                while ((field = MonoApi.mono_class_get_fields(klass, iter)) != 0) {
                    var type = MonoApi.mono_type_get_name(MonoApi.mono_field_get_type(field));
                    var name = MonoApi.mono_field_get_name(field);
                    console.log("\tFiled: " + type.readUtf8String() + "-" + name.readUtf8String());
                }

                // list methods
                iter = Memory.alloc(Process.pointerSize);
                var method;
                // Iterate over all the methods
                while ((method = MonoApi.mono_class_get_methods(klass, iter)) != 0) {
                    var name = MonoApi.mono_method_get_name(method);
                    console.log("\tMethod: " + name.readUtf8String());

                    // list method params
                    var methodsignature = MonoApi.mono_method_signature(method);
                    if (!methodsignature.isNull()) {
                        var rtname = MonoApi.mono_type_get_name(MonoApi.mono_signature_get_return_type(methodsignature));
                        console.log("\t\tReturn: " + rtname.readUtf8String());

                        var paramCount = MonoApi.mono_signature_get_param_count(methodsignature);
                        if (paramCount <= 0) {
                            continue
                        }

                        console.log("Number of params: " + paramCount);
                        var names = Memory.alloc(paramCount * Process.pointerSize);
                        var iter1 = Memory.alloc(Process.pointerSize);

                        MonoApi.mono_method_get_param_names(method, names);
                        for (var i = 0; i < paramCount; i++) {
                            var paramType = MonoApi.mono_signature_get_params(methodsignature, iter1);
                            if (paramType) {
                                var type = MonoApi.mono_class_from_mono_type(paramType);
                                var typeName = Memory.readUtf8String(MonoApi.mono_class_get_name(type));

                                var paramName = Memory.readPointer(names.add(i * Process.pointerSize));
                                console.log("\t\tParam: " + typeName + " " + paramName.readUtf8String());
                            }
                        }
                    }
                }
            }
        }
    }
}, 'void', ['pointer', 'pointer']);


MonoApi.mono_thread_attach(MonoApi.mono_get_root_domain())
MonoApi.mono_assembly_foreach(dumpAllClass, ptr(0));

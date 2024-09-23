// This code references the following source:
// MonoDumper - GrannyConsole.cpp
// URL: https://github.com/xia0ji233/MonoDumper/blob/master/GrannyConsole/GrannyConsole.cpp
// Author: xia0ji233

const MONO_TABLE_TYPEDEF = 2;
const MONO_TOKEN_TYPE_DEF = 0x02000000;

var MonoMoudleName = "libmonobdwgc-2.0.dylib";  // darwin
//                   "mono-2.0-bdwgc.dll";      // windows

var Mono = Process.getModuleByName(MonoMoudleName);

var mono_get_root_domain = new NativeFunction(Mono.getExportByName("mono_get_root_domain"), 'pointer', []);
var mono_thread_attach = new NativeFunction(Mono.getExportByName("mono_thread_attach"), 'pointer', ['pointer']);

var mono_assembly_foreach = new NativeFunction(Mono.getExportByName("mono_assembly_foreach"), 'void', ['pointer', 'pointer']);
var mono_assembly_get_image = new NativeFunction(Mono.getExportByName("mono_assembly_get_image"), 'pointer', ['pointer']);
var mono_image_get_name = new NativeFunction(Mono.getExportByName("mono_image_get_name"), 'pointer', ['pointer']);
var mono_image_get_table_info = new NativeFunction(Mono.getExportByName("mono_image_get_table_info"), 'pointer', ['pointer', 'int']);

var mono_type_get_name = new NativeFunction(Mono.getExportByName("mono_type_get_name"), 'pointer', ['pointer']);
var mono_table_info_get_rows = new NativeFunction(Mono.getExportByName("mono_table_info_get_rows"), 'int', ['pointer']);

var mono_class_get = new NativeFunction(Mono.getExportByName("mono_class_get"), 'pointer', ['pointer', 'int']);
var mono_class_get_name = new NativeFunction(Mono.getExportByName("mono_class_get_name"), 'pointer', ['pointer']);
var mono_class_from_mono_type = new NativeFunction(Mono.getExportByName("mono_class_from_mono_type"), 'pointer', ['pointer'])
var mono_class_get_methods = new NativeFunction(Mono.getExportByName("mono_class_get_methods"), 'pointer', ['pointer', 'pointer']);
var mono_class_get_fields = new NativeFunction(Mono.getExportByName("mono_class_get_fields"), 'pointer', ['pointer', 'pointer']);

var mono_field_get_type = new NativeFunction(Mono.getExportByName("mono_field_get_type"), 'pointer', ['pointer']);
var mono_field_get_name = new NativeFunction(Mono.getExportByName("mono_field_get_name"), 'pointer', ['pointer']);

var mono_method_get_name = new NativeFunction(Mono.getExportByName("mono_method_get_name"), 'pointer', ['pointer']);
var mono_method_get_param_names = new NativeFunction(Mono.getExportByName("mono_method_get_param_names"), 'void', ['pointer', 'pointer']);

var mono_method_signature = new NativeFunction(Mono.getExportByName("mono_method_signature"), 'pointer', ['pointer']);
var mono_signature_get_return_type = new NativeFunction(Mono.getExportByName("mono_signature_get_return_type"), 'pointer', ['pointer']);
var mono_signature_get_param_count = new NativeFunction(Mono.getExportByName("mono_signature_get_param_count"), 'int', ['pointer']);
var mono_signature_get_params = new NativeFunction(Mono.getExportByName("mono_signature_get_params"), 'pointer', ['pointer', 'pointer']);

var dumpAllClass = new NativeCallback(function (assembly, user_data) {
    var image = mono_assembly_get_image(assembly);
    if (image.isNull()) {
        console.log("Image is null for assembly");
        return;
    }

    if (mono_image_get_name(image).readUtf8String() == "Assembly-CSharp") {
        console.log("AssemblyCsharp Found. Assembly object at :" + image);

        // list class
        var table = mono_image_get_table_info(image, MONO_TABLE_TYPEDEF);
        var rows = mono_table_info_get_rows(table);
        console.log("Number of classes in Assembly-CSharp: " + rows);
        // Iterate over all the classes
        for (var i = 0; i < rows; i++) {
            var klass = mono_class_get(image, MONO_TOKEN_TYPE_DEF | (i + 1));
            if (!klass.isNull()) {
                var className = Memory.readUtf8String(mono_class_get_name(klass));
                console.log("Class " + ": " + className);

                // list fields
                var iter = Memory.alloc(Process.pointerSize);
                var field;
                // Iterate over all the fields
                while ((field = mono_class_get_fields(klass, iter)) != 0) {
                    var type = mono_type_get_name(mono_field_get_type(field));
                    var name = mono_field_get_name(field);
                    console.log("\tFiled: " + type.readUtf8String() + "-" + name.readUtf8String());
                }

                // list methods
                iter = Memory.alloc(Process.pointerSize);
                var method;
                // Iterate over all the methods
                while ((method = mono_class_get_methods(klass, iter)) != 0) {
                    var name = mono_method_get_name(method);
                    console.log("\tMethod: " + name.readUtf8String());

                    // list method params
                    var methodsignature = mono_method_signature(method);
                    if (!methodsignature.isNull()) {
                        var rtname = mono_type_get_name(mono_signature_get_return_type(methodsignature));
                        console.log("\t\tReturn: " + rtname.readUtf8String());

                        var paramCount = mono_signature_get_param_count(methodsignature);
                        if (paramCount <= 0) {
                            continue
                        }
                        
                        console.log("Number of params: " + paramCount);
                        var names = Memory.alloc(paramCount * Process.pointerSize);
                        var iter1 = Memory.alloc(Process.pointerSize);

                        mono_method_get_param_names(method, names);
                        for (var i = 0; i < paramCount; i++) {
                            var paramType = mono_signature_get_params(methodsignature, iter1);
                            if (paramType) {
                                var type = mono_class_from_mono_type(paramType);
                                var typeName = Memory.readUtf8String(mono_class_get_name(type));

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


mono_thread_attach(mono_get_root_domain());
mono_assembly_foreach(dumpAllClass, ptr(0));

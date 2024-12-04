Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function (args) {
        args[0] = ptr(-1);
    },
});

Interceptor.attach(Module.findExportByName(null, "task_get_exception_ports"), {
    onEnter: function (args) {
        args[1] = ptr(0);
    },
});

Interceptor.attach(Module.findExportByName(null, "sysctl"), {
    onLeave: function (retval) {
        retval.replace(0x00);
    },
});

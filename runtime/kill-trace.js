/*
 * kill-trace.js — find out exactly what terminates com.example.targetapp.
 * Blocks every termination primitive and logs a backtrace at each call site.
 * Authorized engagement use only.
 *
 *   frida -H 127.0.0.1:40885 -f com.example.targetapp -l runtime/kill-trace.js
 */
'use strict';

(function () {

const log = (m) => send("[kt] " + m);

function gx(sym) {
    try { return Module.findGlobalExportByName(sym); } catch (e) { return null; }
}
function mx(mod, sym) {
    try {
        const m = Process.findModuleByName(mod);
        return m ? m.findExportByName(sym) : null;
    } catch (e) { return null; }
}

function bt(ctx) {
    try {
        return Thread.backtrace(ctx, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress)
            .filter(s => s && s.moduleName)
            .slice(0, 12)
            .map(s => '      ' + s.moduleName + '!' + (s.name || '') + ' @' + s.address)
            .join('\n');
    } catch (e) { return '      <no backtrace>'; }
}

// ---------------------------------------------------------------------------
// Block the process-exit primitives. Each is replaced with a no-op that
// returns to the caller instead of tearing the process down.
// ---------------------------------------------------------------------------
const VOID_EXITS = ['exit', '_exit', '_Exit', 'abort', 'pthread_exit'];
VOID_EXITS.forEach(name => {
    const p = gx(name);
    if (!p) { log('miss ' + name); return; }
    try {
        Interceptor.replace(p, new NativeCallback(function (code) {
            log('!! ' + name + '(' + code + ') BLOCKED  tid=' + Process.getCurrentThreadId() +
                '\n' + bt(this.context));
        }, 'void', ['int']));
        log('armed ' + name);
    } catch (e) { log('fail ' + name + ': ' + e); }
});

['kill', 'tgkill', 'killpg'].forEach(name => {
    const p = gx(name);
    if (!p) { log('miss ' + name); return; }
    try {
        Interceptor.attach(p, {
            onEnter(args) {
                this.sig = args[1].toInt32();
                log('!! ' + name + '(pid=' + args[0].toInt32() + ', sig=' + this.sig + ') tid=' +
                    Process.getCurrentThreadId() + '\n' + bt(this.context));
            }
        });
        log('armed ' + name);
    } catch (e) { log('fail ' + name + ': ' + e); }
});

// raw exit_group / exit syscalls (bypasses libc wrappers)
const sc = gx('syscall');
if (sc) {
    Interceptor.attach(sc, {
        onEnter(args) {
            const nr = args[0].toInt32();
            if (nr === 93 || nr === 94) {   // arm64: exit, exit_group
                log('!! syscall(' + nr + ') tid=' + Process.getCurrentThreadId() +
                    '\n' + bt(this.context));
                args[0] = ptr(1000);        // divert to a harmless syscall nr
            }
        }
    });
    log('armed syscall');
}

// ---------------------------------------------------------------------------
// Java-side termination
// ---------------------------------------------------------------------------
setTimeout(function () {
    if (!Java.available) { log('java not available'); return; }
    Java.perform(function () {
        try {
            const Sys = Java.use('java.lang.System');
            Sys.exit.implementation = function (c) {
                log('!! System.exit(' + c + ') BLOCKED\n' +
                    Java.use('android.util.Log').getStackTraceString(
                        Java.use('java.lang.Exception').$new()));
            };
            log('armed System.exit');
        } catch (e) { log('fail System.exit: ' + e); }
        try {
            const P = Java.use('android.os.Process');
            P.killProcess.implementation = function (pid) {
                log('!! Process.killProcess(' + pid + ') BLOCKED\n' +
                    Java.use('android.util.Log').getStackTraceString(
                        Java.use('java.lang.Exception').$new()));
            };
            log('armed Process.killProcess');
        } catch (e) { log('fail killProcess: ' + e); }
        try {
            const RT = Java.use('java.lang.Runtime');
            RT.exit.implementation = function (c) { log('!! Runtime.exit(' + c + ') BLOCKED'); };
            RT.halt.implementation = function (c) { log('!! Runtime.halt(' + c + ') BLOCKED'); };
            log('armed Runtime.exit/halt');
        } catch (e) { log('fail Runtime: ' + e); }
    });
}, 1500);

// ---------------------------------------------------------------------------
// Watch the protection libraries load, and report libRiskStub detection calls.
// libRiskStub.so ships unstripped C++ symbols, so we can hook them by name.
// ---------------------------------------------------------------------------
const RISK_SYMS = [
    '_Z18acceleration_checkv',
    '_Z10task_speedv',
    '_Z21check_process_stoppedi',
    '_Z20scan_process_threadsi',
    '_Z12doTraceCheckP7_JNIEnvP7_jclass',
    '_Z18capture_debug_flagP7_JNIEnvP7_jclass',
    '_Z11check_fridav',
    '_ZN11ProcessInfo11ptraceCheckEv',
    '_Z26hook_checker_get_proc_mapsP7_JNIEnvP7_jclass'
];

const hooked = {};
function hookRiskStub() {
    const m = Process.findModuleByName('libRiskStub.so');
    if (!m) return false;
    RISK_SYMS.forEach(s => {
        if (hooked[s]) return;
        let p = null;
        try { p = m.findExportByName(s); } catch (e) {}
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter() { this.t0 = Date.now(); },
                onLeave(rv) {
                    log('   ' + s + ' -> ' + rv + '  (' + (Date.now() - this.t0) + 'ms)');
                }
            });
            hooked[s] = true;
            log('armed ' + s);
        } catch (e) { log('fail ' + s + ': ' + e); }
    });
    return true;
}

const dlopen = gx('android_dlopen_ext') || gx('dlopen');
if (dlopen) {
    Interceptor.attach(dlopen, {
        onEnter(args) { try { this.n = args[0].readCString(); } catch (e) { this.n = null; } },
        onLeave() {
            if (this.n && /libRiskStub|libAppGuard|libappsec|libapproov/.test(this.n)) {
                log('dlopen ' + this.n);
                hookRiskStub();
            }
        }
    });
    log('armed dlopen');
}

const iv = setInterval(function () { if (hookRiskStub()) clearInterval(iv); }, 200);

log('ready');

})();

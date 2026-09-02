/*
 * the target app (com.example.targetapp) - SecIron IronSky RASP neutraliser
 * Authorized engagement use only.
 *
 * Targets the 15 detection techniques catalogued in
 * findings/access-by-kai-2026-07-28/deception-analysis.md
 *
 * Detection lives in libAppGuard.so / libRiskStub.so / libappsec.so, all of
 * which are Hikari-obfuscated. We therefore do NOT hook their internal
 * functions by symbol (they're stripped and control-flow-flattened). Instead we
 * hook the libc syscall surface they must ultimately go through, which is
 * stable regardless of how obfuscated the caller is.
 *
 * Usage:
 *   frida -U -f com.example.targetapp -l rasp-bypass.js
 */

'use strict';

(function () {   // IIFE: frida loads every -l script into one global scope,
                 // so keep our identifiers out of it.

// ---------------------------------------------------------------------------
// API compatibility shim.
// Frida 17 REMOVED the old Module-level export lookup. Replacements:
//   global symbol : Module.findGlobalExportByName(sym)
//   module symbol : Process.findModuleByName(mod).findExportByName(sym)
// This shim keeps the script working on both 16.x and 17.x.
//
// NOTE: the legacy function is captured via bracket notation on purpose, so
// the name never appears as a dotted call site (it would otherwise be caught
// by the same search/replace that generated this shim, producing infinite
// recursion).
// ---------------------------------------------------------------------------
const _legacyFind = Module['find' + 'ExportByName'];

function resolveExport(moduleName, symbol) {
    try {
        if (moduleName === null || moduleName === undefined) {
            if (typeof Module.findGlobalExportByName === 'function')
                return Module.findGlobalExportByName(symbol);
        } else {
            if (typeof Process.findModuleByName === 'function') {
                const m = Process.findModuleByName(moduleName);
                if (m && typeof m.findExportByName === 'function')
                    return m.findExportByName(symbol);
            }
        }
        // Frida <= 16 fallback
        if (typeof _legacyFind === 'function')
            return _legacyFind.call(Module, moduleName, symbol);
    } catch (e) { /* fall through */ }
    return null;
}

// ---------------------------------------------------------------------------
// Path denylist - anything the RASP probes for to conclude "rooted/hooked"
// Derived from strings in libAppGuard.so and libRiskStub.so.
// ---------------------------------------------------------------------------
const BLOCKED_PATH_SUBSTRINGS = [
    'magisk', 'Magisk', '.magisk',
    '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin',
    'busybox', 'superuser', 'Superuser', 'supersu', 'SuperSU',
    'frida', 'Frida', 'gum-js', 'gadget',
    'xposed', 'Xposed', 'dexposed', 'substrate', 'riru', 'zygisk', 'lsposed',
    're.frida.server', 'com.topjohnwu.magisk', 'eu.chainfire',
    // integrity probes - let these fail closed rather than reveal a patched env
    '/system/build.prop',
    '/proc/self/mounts', '/proc/self/mountinfo',
];

// /proc/<pid>/maps and friends get special treatment: we allow the open but
// scrub the contents (see readScrubber below), because failing the open
// outright is itself a detectable anomaly.
const SCRUBBED_PATHS = ['/maps', '/mountinfo', '/mounts', '/status', '/cmdline', '/task'];

// Substrings scrubbed out of any /proc read
const MAPS_NEEDLES = [
    'frida', 'gum-js', 'gadget', 'linjector',
    'magisk', 'xposed', 'substrate', 'riru', 'zygisk',
];

function pathIsBlocked(p) {
    if (!p) return false;
    for (const s of BLOCKED_PATH_SUBSTRINGS) if (p.indexOf(s) !== -1) return true;
    return false;
}

function pathIsScrubbed(p) {
    if (!p || p.indexOf('/proc/') !== 0) return false;
    for (const s of SCRUBBED_PATHS) if (p.indexOf(s) !== -1) return true;
    return false;
}

const log = (m) => console.log('[rasp] ' + m);

// ---------------------------------------------------------------------------
// 1. File-existence probes: open / openat / fopen / access / stat / lstat
//    Covers: root binaries, magisk paths, frida artifacts, emulator libs
// ---------------------------------------------------------------------------
const scrubFds = {};   // fd -> true, for /proc files we want to filter on read

function hookOpenFamily() {
    ['open', 'openat', 'fopen', 'access', 'stat', 'lstat', 'stat64', 'lstat64', '__xstat', 'faccessat']
    .forEach(function (fn) {
        const addr = resolveExport('libc.so', fn);
        if (!addr) return;

        // argument index holding the path differs for the *at() variants
        const pathArg = (fn === 'openat' || fn === 'faccessat') ? 1 : 0;

        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.blocked = false;
                this.scrub = false;
                try {
                    this.path = args[pathArg].readCString();
                } catch (e) { this.path = null; }

                if (pathIsBlocked(this.path)) {
                    this.blocked = true;
                    log('blocked ' + fn + '("' + this.path + '")');
                } else if (pathIsScrubbed(this.path) && (fn === 'open' || fn === 'openat' || fn === 'fopen')) {
                    this.scrub = true;
                }
            },
            onLeave: function (retval) {
                if (this.blocked) {
                    // ENOENT-equivalent for each family
                    if (fn === 'fopen') retval.replace(ptr(0));
                    else retval.replace(ptr(-1));
                    return;
                }
                if (this.scrub && !retval.isNull() && retval.toInt32() !== -1) {
                    scrubFds[retval.toInt32()] = true;
                }
            }
        });
    });
    log('hooked open/stat/access family');
}

// ---------------------------------------------------------------------------
// 2. /proc/self/maps content scrubbing
//    The RASP reads its own memory map looking for frida-agent / gum-js.
//    We let the read succeed but strip offending lines.
// ---------------------------------------------------------------------------
function hookReads() {
    const readAddr = resolveExport('libc.so', 'read');
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.want = scrubFds[this.fd] === true;
            },
            onLeave: function (retval) {
                if (!this.want) return;
                const n = retval.toInt32();
                if (n <= 0) return;
                let data;
                try { data = this.buf.readUtf8String(n); } catch (e) { return; }
                if (!data) return;

                let dirty = false;
                for (const needle of MAPS_NEEDLES) {
                    if (data.toLowerCase().indexOf(needle) !== -1) { dirty = true; break; }
                }
                if (!dirty) return;

                const cleaned = data.split('\n').filter(function (line) {
                    const l = line.toLowerCase();
                    for (const needle of MAPS_NEEDLES) if (l.indexOf(needle) !== -1) return false;
                    return true;
                }).join('\n');

                try {
                    this.buf.writeUtf8String(cleaned);
                    retval.replace(ptr(cleaned.length));
                    log('scrubbed ' + (n - cleaned.length) + ' bytes from /proc read (fd ' + this.fd + ')');
                } catch (e) { /* buffer too small to rewrite - leave as-is */ }
            }
        });
    }

    // fgets is the more common way to walk /proc/self/maps line by line
    const fgetsAddr = resolveExport('libc.so', 'fgets');
    if (fgetsAddr) {
        Interceptor.attach(fgetsAddr, {
            onEnter: function (args) { this.buf = args[0]; },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                let line;
                try { line = this.buf.readCString(); } catch (e) { return; }
                if (!line) return;
                const l = line.toLowerCase();
                for (const needle of MAPS_NEEDLES) {
                    if (l.indexOf(needle) !== -1) {
                        // replace with a benign-looking mapping rather than empty,
                        // so line-count heuristics don't trip
                        try {
                            this.buf.writeUtf8String(
                                '7f0000000000-7f0000001000 r--p 00000000 fd:00 1 /system/lib64/libc.so\n');
                        } catch (e) {}
                        log('rewrote maps line containing "' + needle + '"');
                        return;
                    }
                }
            }
        });
    }
    log('hooked read/fgets for /proc scrubbing');
}

// ---------------------------------------------------------------------------
// 3. strstr - the classic RASP primitive.
//    libAppGuard reads a blob then strstr()s for "frida-agent", "magisk", etc.
//    Returning NULL for those needles kills a whole class of checks at once.
// ---------------------------------------------------------------------------
function hookStrstr() {
    const addr = resolveExport('libc.so', 'strstr');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.lie = false;
            try {
                const needle = args[1].readCString();
                if (!needle) return;
                const n = needle.toLowerCase();
                for (const bad of MAPS_NEEDLES) {
                    if (n.indexOf(bad) !== -1) { this.lie = true; this.needle = needle; break; }
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.lie) {
                retval.replace(ptr(0));
                log('strstr("' + this.needle + '") -> NULL');
            }
        }
    });
    log('hooked strstr');
}

// ---------------------------------------------------------------------------
// 4. ptrace anti-debug (PTRACE_TRACEME = 0) and TracerPid
// ---------------------------------------------------------------------------
function hookPtrace() {
    const addr = resolveExport('libc.so', 'ptrace');
    if (!addr) return;
    Interceptor.replace(addr, new NativeCallback(function (request, pid, addr_, data) {
        // pretend every ptrace request succeeded without actually attaching
        return 0;
    }, 'long', ['int', 'int', 'pointer', 'pointer']));
    log('neutralised ptrace');
}

// ---------------------------------------------------------------------------
// 5. Frida default-port scan (RASP string: "Host: 127.0.0.1:27042")
//    Block connect() to the frida port range so the probe times out negative.
// ---------------------------------------------------------------------------
function hookConnect() {
    const addr = resolveExport('libc.so', 'connect');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.block = false;
            try {
                const sa = args[1];
                const family = sa.readU16();
                if (family !== 2) return;                    // AF_INET only
                const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                if (port >= 27000 && port <= 27100) {        // frida default band
                    this.block = true;
                    log('blocked connect() to port ' + port + ' (frida probe)');
                }
            } catch (e) {}
        },
        onLeave: function (retval) { if (this.block) retval.replace(ptr(-1)); }
    });
    log('hooked connect');
}

// ---------------------------------------------------------------------------
// 6. Java tier - PackageManager queries for Magisk/Superuser, Build props
// ---------------------------------------------------------------------------
function hookJava() {
    if (!Java.available) return;
    Java.perform(function () {
        try {
            const PM = Java.use('android.app.ApplicationPackageManager');
            PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (name, flags) {
                if (name && /magisk|superuser|supersu|xposed|frida|chainfire/i.test(name)) {
                    log('PackageManager.getPackageInfo("' + name + '") -> NameNotFound');
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(name);
                }
                return this.getPackageInfo(name, flags);
            };
        } catch (e) { log('PM hook skipped: ' + e); }

        try {
            const Build = Java.use('android.os.Build');
            Build.TAGS.value = 'release-keys';
            Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace(/test-keys/g, 'release-keys');
        } catch (e) {}

        try {
            const Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function () { return false; };
        } catch (e) {}

        log('Java-tier hooks installed');
    });
}

// ---------------------------------------------------------------------------
// Install everything before the protection libs get a chance to run.
// dlopen is hooked so we can log when the RASP libraries actually load.
// ---------------------------------------------------------------------------
function watchLibraryLoads() {
    const dlopen = resolveExport(null, 'android_dlopen_ext')
                || resolveExport(null, 'dlopen');
    if (!dlopen) return;
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            try { this.lib = args[0].readCString(); } catch (e) { this.lib = null; }
        },
        onLeave: function () {
            if (!this.lib) return;
            if (/AppGuard|RiskStub|appsec|approov/i.test(this.lib)) {
                log('protection library loaded: ' + this.lib);
            }
        }
    });
}

log('installing hooks...');
watchLibraryLoads();
hookOpenFamily();
hookReads();
hookStrstr();
hookPtrace();
hookConnect();
hookJava();
log('ready - RASP surface neutralised');

})();

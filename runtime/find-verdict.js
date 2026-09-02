/*
 * find-verdict.js — locate the code that decides "Run on Emulator" and shows
 * the "Infomation / Cannot run due to ..." dialog.
 * Authorized engagement use only.
 *
 *   frida -H 127.0.0.1:40885 -f com.example.targetapp -l runtime/find-verdict.js
 */
'use strict';

(function () {

const log = (m) => console.log('[fv] ' + m);

// ---------------------------------------------------------------------------
// Native module inventory — which protection libs actually get loaded?
// ---------------------------------------------------------------------------
function dumpModules(tag) {
    try {
        const mods = Process.enumerateModules()
            .filter(m => /AppGuard|RiskStub|appsec|approov|coralline|everisk|sec/i.test(m.name));
        log(tag + ' protection modules: ' +
            (mods.length ? mods.map(m => m.name + '@' + m.base + '(' + m.size + ')').join(', ')
                         : '<none>'));
    } catch (e) { log('module dump failed: ' + e); }
}

const dl = Module.findGlobalExportByName('android_dlopen_ext');
if (dl) {
    Interceptor.attach(dl, {
        onEnter(a) { try { this.n = a[0].readCString(); } catch (e) { this.n = null; } },
        onLeave() { if (this.n && /\.so$/.test(this.n)) log('dlopen ' + this.n); }
    });
    log('armed dlopen');
}

setTimeout(() => dumpModules('t+3s'), 3000);
setTimeout(() => dumpModules('t+10s'), 10000);

// ---------------------------------------------------------------------------
// Java side: catch whatever renders the verdict text.
// ---------------------------------------------------------------------------
function javaStack() {
    try {
        return Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new());
    } catch (e) { return '<no stack>'; }
}

const HIT = /Emulator|Cannot run|Infomation|Information|rooted|root|debugger|hook/i;

setTimeout(function () {
    if (!Java.available) { log('java unavailable'); return; }
    Java.perform(function () {

        // 1) AlertDialog.Builder text
        ['android.app.AlertDialog$Builder',
         'androidx.appcompat.app.AlertDialog$Builder'].forEach(function (cn) {
            let C;
            try { C = Java.use(cn); } catch (e) { return; }
            ['setMessage', 'setTitle'].forEach(function (mn) {
                try {
                    C[mn].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            const v = arguments.length ? String(arguments[0]) : '';
                            if (HIT.test(v)) {
                                log('!! ' + cn.split('.').pop() + '.' + mn + '("' + v + '")\n' + javaStack());
                            }
                            return ov.apply(this, arguments);
                        };
                    });
                } catch (e) {}
            });
            log('armed ' + cn);
        });

        // 2) TextView.setText — Flutter apps often render native dialogs this way
        try {
            const TV = Java.use('android.widget.TextView');
            TV.setText.overload('java.lang.CharSequence').implementation = function (cs) {
                const v = cs ? String(cs) : '';
                if (HIT.test(v)) log('!! TextView.setText("' + v + '")\n' + javaStack());
                return this.setText(cs);
            };
            log('armed TextView.setText');
        } catch (e) { log('TextView fail: ' + e); }

        // 3) Toast
        try {
            const T = Java.use('android.widget.Toast');
            T.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
             .implementation = function (c, s, d) {
                const v = s ? String(s) : '';
                if (HIT.test(v)) log('!! Toast("' + v + '")\n' + javaStack());
                return this.makeText(c, s, d);
            };
            log('armed Toast');
        } catch (e) {}

        // 4) String constructor is far too hot to hook; instead watch the two
        //    packer entry classes for any method that returns the verdict.
        ['com.coralline.sea.dd', 'com.AppGuard.AppGuard.T64'].forEach(function (cn) {
            try { Java.use(cn); log('class present: ' + cn); }
            catch (e) { log('class absent: ' + cn); }
        });

        // 5) Enumerate loaded classes that look RASP-ish, once.
        try {
            const seen = [];
            Java.enumerateLoadedClassesSync().forEach(function (c) {
                if (/coralline|AppGuard|everisk|seciron|ironsky|walljar|fort/i.test(c)) seen.push(c);
            });
            log('RASP classes loaded (' + seen.length + '): ' + seen.slice(0, 40).join(', '));
        } catch (e) { log('enumerate failed: ' + e); }
    });
}, 2000);

log('ready');

})();

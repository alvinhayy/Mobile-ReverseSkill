/*
 * verdict-hook.js — catch the RASP verdict UI and report the Java call stack
 * that produced it. Concatenated after emu-bypass.js into a frida-compile
 * agent (Frida 17 dropped the built-in Java bridge).
 * Authorized engagement use only.
 */

const VERDICT_RE = /Emulator|Cannot run|Infomation|Information|Root|JailBreak|Beaware|hook|debug/i;

function javaStack() {
    try {
        return Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new());
    } catch (e) { return '<no stack>'; }
}

function armVerdict() {
    Java.perform(function () {

        // Dialog builders
        ['android.app.AlertDialog$Builder',
         'androidx.appcompat.app.AlertDialog$Builder'].forEach(function (cn) {
            let C;
            try { C = Java.use(cn); } catch (e) { return; }
            ['setMessage', 'setTitle'].forEach(function (mn) {
                try {
                    C[mn].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            const v = arguments.length && arguments[0] != null
                                ? String(arguments[0]) : '';
                            if (VERDICT_RE.test(v))
                                send('VERDICT ' + cn.split('.').pop() + '.' + mn +
                                     '("' + v + '")\n' + javaStack());
                            return ov.apply(this, arguments);
                        };
                    });
                } catch (e) {}
            });
        });

        // TextView.setText — covers custom dialog layouts
        try {
            const TV = Java.use('android.widget.TextView');
            TV.setText.overload('java.lang.CharSequence').implementation = function (cs) {
                const v = cs != null ? String(cs) : '';
                if (VERDICT_RE.test(v)) send('VERDICT TextView.setText("' + v + '")\n' + javaStack());
                return this.setText(cs);
            };
        } catch (e) {}

        // Toast
        try {
            const T = Java.use('android.widget.Toast');
            T.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
             .implementation = function (c, s, d) {
                const v = s != null ? String(s) : '';
                if (VERDICT_RE.test(v)) send('VERDICT Toast("' + v + '")\n' + javaStack());
                return this.makeText(c, s, d);
            };
        } catch (e) {}

        // Termination paths — observe only, do not block (blocking exit() and
        // returning into the caller corrupts control flow and segfaults).
        try {
            Java.use('java.lang.System').exit.implementation = function (c) {
                send('TERM System.exit(' + c + ')\n' + javaStack());
                return this.exit(c);
            };
        } catch (e) {}
        try {
            Java.use('android.os.Process').killProcess.implementation = function (p) {
                send('TERM Process.killProcess(' + p + ')\n' + javaStack());
                return this.killProcess(p);
            };
        } catch (e) {}
        try {
            const RT = Java.use('java.lang.Runtime');
            RT.exit.implementation = function (c) { send('TERM Runtime.exit(' + c + ')\n' + javaStack()); return this.exit(c); };
            RT.halt.implementation = function (c) { send('TERM Runtime.halt(' + c + ')\n' + javaStack()); return this.halt(c); };
        } catch (e) {}

        send('verdict hooks armed');
    });
}

let vDone = false;
const vPoll = setInterval(function () {
    if (vDone) { clearInterval(vPoll); return; }
    try {
        if (typeof Java === 'undefined' || !Java.available) return;
        vDone = true;
        clearInterval(vPoll);
        armVerdict();
    } catch (e) {}
}, 25);

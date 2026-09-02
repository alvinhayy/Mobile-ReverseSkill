/*
 * rasp-neutralise.js — stop SecIron everisk from acting on its risk verdict.
 * Authorized engagement use only.
 *
 * Verdict path recovered live (see runtime/verdict-hook.js output):
 *
 *   RiskStubAPI$BroadcastReceiver$1.run
 *     -> com.appsec.everisk.core.UiUtil.showDialogV2
 *          -> RiskDialog.onCreate  ("Infomation" / "Cannot run due to Run on Emulator")
 *     -> java.lang.System.exit(0)
 *
 * The detection itself is left intact; only the reaction is suppressed. Java
 * `System.exit` is neutralised at the Java level rather than by replacing the
 * native exit(), because returning from a replaced native exit() corrupts the
 * caller's control flow and segfaults the process.
 */

function armNeutralise() {
    Java.perform(function () {

        // 1. Suppress the risk dialog.
        try {
            const U = Java.use('com.appsec.everisk.core.UiUtil');
            let n = 0;
            Object.keys(U).forEach(function (k) {
                if (!/^showDialog/.test(k)) return;
                try {
                    U[k].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            send('BLOCKED UiUtil.' + k + '()');
                            return null;
                        };
                        n++;
                    });
                } catch (e) {}
            });
            send('armed UiUtil showDialog* (' + n + ' overloads)');
        } catch (e) { send('UiUtil hook failed: ' + e); }

        // 2. Suppress the dialog class itself, in case another path shows it.
        try {
            const D = Java.use('com.appsec.everisk.core.RiskDialog');
            D.show.overloads.forEach(function (ov) {
                ov.implementation = function () { send('BLOCKED RiskDialog.show()'); };
            });
            send('armed RiskDialog.show');
        } catch (e) { /* class may not expose show() */ }

        // 3. Block the termination the receiver performs afterwards.
        try {
            Java.use('java.lang.System').exit.implementation = function (c) {
                send('BLOCKED System.exit(' + c + ')');
            };
            send('armed System.exit');
        } catch (e) { send('System.exit hook failed: ' + e); }

        try {
            const RT = Java.use('java.lang.Runtime');
            RT.exit.implementation = function (c) { send('BLOCKED Runtime.exit(' + c + ')'); };
            RT.halt.implementation = function (c) { send('BLOCKED Runtime.halt(' + c + ')'); };
            send('armed Runtime.exit/halt');
        } catch (e) {}

        try {
            Java.use('android.os.Process').killProcess.implementation = function (p) {
                send('BLOCKED Process.killProcess(' + p + ')');
            };
            send('armed Process.killProcess');
        } catch (e) {}

        send('rasp-neutralise ready');
    });
}

let nDone = false;
const nPoll = setInterval(function () {
    if (nDone) { clearInterval(nPoll); return; }
    try {
        if (typeof Java === 'undefined' || !Java.available) return;
        nDone = true;
        clearInterval(nPoll);
        armNeutralise();
    } catch (e) {}
}, 25);

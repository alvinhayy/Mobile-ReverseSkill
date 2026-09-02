/*
 * ua-spoof.js — hilangkan kebocoran identitas emulator lewat User-Agent.
 * Authorized engagement use only.
 *
 * Masalah: `http.agent` disusun saat VM init dari Build.MODEL/VERSION/ID —
 * jauh sebelum hook Java kita jalan (~3.3s). Akibatnya request tetap membawa:
 *
 *   User-Agent: Dalvik/2.1.0 (Linux; U; Android 16; sdk_gphone64_arm64 Build/BE2A.250530.026.D1)
 *
 * Spoof Build.* saja tidak cukup karena string UA sudah ter-cache.
 * Di sini: set ulang properti `http.agent`, intercept pembacaannya, dan
 * tulis ulang header User-Agent di lapisan HTTP (Java + OkHttp) sebagai jaring
 * pengaman. Dart/Flutter memakai UA sendiri (`Dart/x.y (dart:io)`) yang tidak
 * membocorkan model perangkat, jadi tidak diubah.
 */

const UA_FAKE = 'Dalvik/2.1.0 (Linux; U; Android 13; SM-A536B Build/TP1A.220624.014)';
const UA_LEAK = /sdk_gphone|generic|emu64|ranchu|goldfish|Android 16/i;

function armUa() {
    Java.perform(function () {

        // 1. Ganti nilai properti yang sudah ter-cache.
        try {
            const Sys = Java.use('java.lang.System');
            const before = Sys.getProperty('http.agent');
            Sys.setProperty('http.agent', UA_FAKE);
            send('UA http.agent: "' + before + '" -> "' + Sys.getProperty('http.agent') + '"');

            // 2. Intercept pembacaan berikutnya (kalau ada yang cache ulang).
            Sys.getProperty.overload('java.lang.String').implementation = function (k) {
                const v = this.getProperty(k);
                if (k === 'http.agent' || (v && UA_LEAK.test(v) && /agent/i.test(k))) return UA_FAKE;
                return v;
            };
            Sys.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) {
                const v = this.getProperty(k, d);
                if (k === 'http.agent' || (v && UA_LEAK.test(v) && /agent/i.test(k))) return UA_FAKE;
                return v;
            };
            send('armed System.getProperty(http.agent)');
        } catch (e) { send('http.agent spoof failed: ' + e); }

        // 3. Jaring pengaman di lapisan HTTP: tulis ulang header apa pun yang bocor.
        try {
            const URLC = Java.use('java.net.URLConnection');
            URLC.setRequestProperty.implementation = function (k, v) {
                if (k && k.toLowerCase() === 'user-agent' && v && UA_LEAK.test(v)) {
                    send('UA rewrite (URLConnection): "' + v + '"');
                    return this.setRequestProperty(k, UA_FAKE);
                }
                return this.setRequestProperty(k, v);
            };
            URLC.addRequestProperty.implementation = function (k, v) {
                if (k && k.toLowerCase() === 'user-agent' && v && UA_LEAK.test(v)) {
                    return this.addRequestProperty(k, UA_FAKE);
                }
                return this.addRequestProperty(k, v);
            };
            send('armed URLConnection UA rewrite');
        } catch (e) { /* kelas mungkin tidak dipakai */ }

        try {
            const B = Java.use('okhttp3.Request$Builder');
            ['header', 'addHeader'].forEach(function (mn) {
                try {
                    B[mn].overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                        if (k && k.toLowerCase() === 'user-agent' && v && UA_LEAK.test(v)) {
                            send('UA rewrite (okhttp): "' + v + '"');
                            return this[mn](k, UA_FAKE);
                        }
                        return this[mn](k, v);
                    };
                } catch (e) {}
            });
            send('armed okhttp UA rewrite');
        } catch (e) { /* okhttp mungkin di-shade / tidak ada */ }

        send('ua-spoof ready');
    });
}

let uaDone = false;
const uaPoll = setInterval(function () {
    if (uaDone) { clearInterval(uaPoll); return; }
    try {
        if (typeof Java === 'undefined' || !Java.available) return;
        uaDone = true;
        clearInterval(uaPoll);
        armUa();
    } catch (e) {}
}, 25);

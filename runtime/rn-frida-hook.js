/* rn-frida-hook.js — React Native dynamic instrumentation (Java side, version-tolerant).
 * frida -U -f <pkg> -l runtime/rn-frida-hook.js   (authorized targets only)
 * Logs: RN network (OkHttp req/resp), the JS<->native bridge, AsyncStorage I/O, and the JS
 * bundle path. Pair with ssl-pinning-universal.js so HTTPS is visible.  */
Java.perform(function () {
  function tryHook(name, fn) { try { fn(); console.log("[rn] hooked " + name); } catch (e) {} }

  // 1) Network — RN routes fetch/XHR through OkHttp
  tryHook("OkHttp Request/Response", function () {
    var RealCall = Java.use("okhttp3.RealCall");
    RealCall.execute.implementation = function () {
      try { console.log("[rn][http] -> " + this.request().method() + " " + this.request().url()); } catch (e) {}
      var resp = this.execute();
      try { console.log("[rn][http] <- " + resp.code() + " " + this.request().url()); } catch (e) {}
      return resp;
    };
  });
  tryHook("OkHttp RequestBody (post data)", function () {
    var Buffer = Java.use("okio.Buffer");
    var RequestBody = Java.use("okhttp3.RequestBody");
    // best-effort: log string bodies via the request builder is version-specific; skip if absent
  });

  // 2) JS <-> native bridge — see which native modules JS calls
  tryHook("CatalystInstanceImpl.callFunction", function () {
    var CI = Java.use("com.facebook.react.bridge.CatalystInstanceImpl");
    CI.callFunction.overload('java.lang.String', 'java.lang.String', 'com.facebook.react.bridge.NativeArray')
      .implementation = function (mod, method, args) {
        console.log("[rn][bridge] JS->native " + mod + "." + method);
        return this.callFunction(mod, method, args);
      };
  });

  // 3) AsyncStorage — plaintext local storage used by most RN apps
  ["com.reactnativecommunity.asyncstorage.AsyncStorageModule",
   "com.facebook.react.modules.storage.AsyncStorageModule"].forEach(function (cls) {
    tryHook(cls + ".multiGet/multiSet", function () {
      var AS = Java.use(cls);
      if (AS.multiSet) AS.multiSet.overload('com.facebook.react.bridge.ReadableArray', 'com.facebook.react.bridge.Callback')
        .implementation = function (kv, cb) { console.log("[rn][storage] SET " + kv.toString()); return this.multiSet(kv, cb); };
      if (AS.multiGet) AS.multiGet.overload('com.facebook.react.bridge.ReadableArray', 'com.facebook.react.bridge.Callback')
        .implementation = function (keys, cb) { console.log("[rn][storage] GET " + keys.toString()); return this.multiGet(keys, cb); };
    });
  });

  // 4) JS bundle path (also the injection point if you want to prepend JS)
  ["com.facebook.react.bridge.CatalystInstanceImpl", "com.facebook.hermes.reactexecutor.HermesExecutor"]
    .forEach(function (c) {
      tryHook(c + ".loadScriptFrom*", function () {
        var K = Java.use(c);
        ["loadScriptFromAssets", "loadScriptFromFile"].forEach(function (m) {
          if (K[m]) K[m].overloads.forEach(function (ov) {
            ov.implementation = function () {
              try { console.log("[rn][bundle] " + m + "(" + Array.prototype.slice.call(arguments).join(", ") + ")"); } catch (e) {}
              return ov.apply(this, arguments);
            };
          });
        });
      });
    });

  console.log("[+] rn-frida-hook loaded (attach ssl-pinning-universal.js too for HTTPS bodies)");
});

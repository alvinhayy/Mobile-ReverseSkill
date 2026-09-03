/* flutter-tls-connect-redirect.js — intercept Flutter/Dart HTTPS when standard unpinning fails.
 * Dart's HttpClient IGNORES the system proxy, so unpinning alone isn't enough. This redirects
 * outbound TCP to your proxy and injects an HTTP CONNECT so the proxy learns the real host.
 * Pair with flutter-tls.js (which patches ssl_verify_peer_cert). Run mitmproxy in REGULAR mode.
 *   frida -U -f <pkg> -l runtime/flutter-tls.js -l runtime/flutter-tls-connect-redirect.js
 * GOTCHA: on an x86_64 emulator the arm64 libflutter runs under libndk_translation and is
 * invisible to Frida — use a PHYSICAL ARM64 device.  (technique: randywestergren, NVISO)  */
var PROXY_HOST = '127.0.0.1';   // mitmproxy/Burp reachable from the device (emulator: 10.0.2.2)
var PROXY_PORT = 8080;
var pending = {};               // fd -> "host:port" awaiting a CONNECT preamble

function ipStr(p){ return p.readU8()+'.'+p.add(1).readU8()+'.'+p.add(2).readU8()+'.'+p.add(3).readU8(); }

var connectPtr = Module.findExportByName(null, 'connect');
if (connectPtr) Interceptor.attach(connectPtr, {
  onEnter: function (args) {
    try {
      var fd = args[0].toInt32(), sa = args[1];
      if (sa.isNull() || sa.readU16() !== 2) return;              // AF_INET only
      var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      var ip = ipStr(sa.add(4));
      if (ip === PROXY_HOST && port === PROXY_PORT) return;       // already the proxy
      pending[fd] = ip + ':' + port;
      sa.add(2).writeU8((PROXY_PORT >> 8) & 0xff); sa.add(3).writeU8(PROXY_PORT & 0xff);
      var o = PROXY_HOST.split('.'); for (var i = 0; i < 4; i++) sa.add(4 + i).writeU8(parseInt(o[i], 10));
      console.log('[flutter-proxy] redirect fd=' + fd + ' -> ' + ip + ':' + port + ' via proxy');
    } catch (e) {}
  }
});

['send', 'write'].forEach(function (fn) {
  var p = Module.findExportByName(null, fn); if (!p) return;
  var w = new NativeFunction(p, 'long', ['int', 'pointer', 'ulong']);
  Interceptor.attach(p, {
    onEnter: function (args) {
      var fd = args[0].toInt32(); var dest = pending[fd]; if (!dest) return;
      delete pending[fd];
      var c = 'CONNECT ' + dest + ' HTTP/1.1\r\nHost: ' + dest + '\r\n\r\n';
      try { var buf = Memory.allocUtf8String(c); w(fd, buf, c.length); } catch (e) {}
    }
  });
});
console.log('[+] flutter-tls-connect-redirect loaded (proxy ' + PROXY_HOST + ':' + PROXY_PORT + ', mitmproxy regular mode)');

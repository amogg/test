(function() {
    send("==================================================");
    send("[*] Starting API Tracer (Discovering actual calls)");
    send("[*] Target: Network, File, Crypto APIs");
    send("==================================================");

    // 중복 후킹 방지용
    var hookedPtrs = {};

    // [1] 안전한 후킹 함수
    function traceFunction(modName, funcName) {
        // 주소 찾기
        var ptr = null;
        try { ptr = Module.findExportByName(modName, funcName); } catch(e) {}
        
        if (!ptr) return;
        if (hookedPtrs[ptr]) return; // 이미 후킹됨

        try {
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    // 호출되면 함수 이름만 찍음
                    send("\x1b[33m[HIT] " + modName + "!" + funcName + "\x1b[0m");
                }
            });
            hookedPtrs[ptr] = true;
        } catch(e) {}
    }

    // [2] 모듈 내의 함수들을 패턴으로 검색해서 일괄 후킹
    function traceModule(modName, patterns) {
        var m = null;
        try { m = Process.findModuleByName(modName); } catch(e) {}
        
        if (!m) {
            // send("[-] Module not found: " + modName);
            return;
        }

        send("[*] Scanning " + modName + " for keywords: " + patterns.join(", "));

        try {
            var exports = Module.enumerateExports(modName);
            var count = 0;

            for (var i = 0; i < exports.length; i++) {
                var name = exports[i].name;
                var lowName = name.toLowerCase();

                // 패턴 매칭
                for (var j = 0; j < patterns.length; j++) {
                    if (lowName.indexOf(patterns[j]) !== -1) {
                        traceFunction(modName, name);
                        count++;
                        break;
                    }
                }
            }
            send("    -> Hooked " + count + " functions in " + modName);
        } catch(e) {
            send("[!] Error enumerating " + modName + ": " + e.message);
        }
    }

    // =========================================================================
    // [3] 감시 대상 설정 (여기가 핵심입니다)
    // =========================================================================
    
    // 1초마다 모듈 로드 확인 (Lazy Loading 대응)
    setInterval(function() {
        
        // 1. 네트워크 (Winsock) - 가장 낮은 단계
        // send, recv, connect, select, wsa... 등이 호출되는지 확인
        traceModule("ws2_32.dll", ["send", "recv", "connect", "select", "wsasend", "wsarecv"]);

        // 2. 파일 시스템 (Kernel32)
        // createfile, writefile, readfile
        traceModule("kernel32.dll", ["createfile", "writefile", "readfile"]);

        // 3. SSL/Crypto (Windows Native)
        // decrypt, encrypt, initialize, context
        traceModule("SspiCli.dll", ["decrypt", "encrypt", "context"]);
        traceModule("Secur32.dll", ["decrypt", "encrypt"]);

        // 4. OpenSSL / 기타 SSL (모든 로드된 모듈 대상)
        // ssl_read, ssl_write, bio_read, bio_write
        // (주의: 너무 많을 수 있으니 패턴을 구체적으로)
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var mName = modules[i].name.toLowerCase();
            if (mName.indexOf("ssl") !== -1 || mName.indexOf("crypto") !== -1 || mName.indexOf("tls") !== -1) {
                traceModule(modules[i].name, ["read", "write", "decrypt", "encrypt"]);
            }
        }

    }, 2000); // 2초마다 스캔 (부하 줄임)

})();

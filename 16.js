(function() {
    console.log("==================================================");
    console.log("[*] Starting Robust Hybrid SSL Hooking");
    console.log("==================================================");

    // [1] 유틸리티: 덤프 (hexdump가 없는 경우 대비)
    function dumpMemory(ptr, length) {
        if (ptr.isNull() || length <= 0) return "";
        try {
            var dumpLen = Math.min(length, 256);
            var buf = ptr.readByteArray(dumpLen);
            
            // hexdump 함수 존재 여부 확인
            if (typeof hexdump === 'function') {
                var str = "\\n" + hexdump(buf, { offset: 0, length: dumpLen, header: false, ansi: false });
                if (length > dumpLen) str += "\\n... (truncated " + (length - dumpLen) + " bytes) ...";
                return str;
            } else {
                return " (hexdump function not available)";
            }
        } catch (e) { return "(dump error: " + e.message + ")"; }
    }

    // [2] 유틸리티: 주소 해결사 (Resolve Address) - 에러 원인 차단
    function resolveAddress(moduleName, funcName) {
        var ptr = null;
        
        // 1차 시도: Module.findExportByName
        try {
            if (Module && typeof Module.findExportByName === 'function') {
                ptr = Module.findExportByName(moduleName, funcName);
            }
        } catch(e) {}

        if (ptr) return ptr;

        // 2차 시도: Process.findModuleByName -> Module.findExportByName
        try {
            if (Process && typeof Process.findModuleByName === 'function') {
                var m = Process.findModuleByName(moduleName);
                if (m && Module && typeof Module.findExportByName === 'function') {
                    ptr = Module.findExportByName(m.name, funcName);
                }
            }
        } catch(e) {}
        
        return ptr;
    }

    // [3] 안전한 후킹 래퍼 (SafeHook)
    function safeHook(moduleName, funcName, callbacks) {
        try {
            var ptr = resolveAddress(moduleName, funcName);
            
            if (ptr) {
                Interceptor.attach(ptr, callbacks);
                console.log("[+] Hooked: " + moduleName + "!" + funcName + " (@ " + ptr + ")");
            } else {
                console.log("[-] Not Found (Skip): " + moduleName + "!" + funcName);
            }
        } catch (e) {
            console.log("[!] Hook Failed: " + moduleName + "!" + funcName + " - " + e.message);
        }
    }

    // =========================================================================
    // Part 1. Windows Native SSL (SspiCli.dll)
    // =========================================================================
    safeHook("SspiCli.dll", "DecryptMessage", {
        onEnter: function(args) { this.pMessage = args[1]; },
        onLeave: function(retval) {
            if (retval.toInt32() === 0 && this.pMessage) {
                try {
                    var cBuffers = this.pMessage.add(4).readU32(); // 개수
                    var pBuffers = this.pMessage.add(8).readPointer(); // 포인터
                    
                    for (var i = 0; i < cBuffers; i++) {
                        var secBuffer = pBuffers.add(i * 16); 
                        var type = secBuffer.add(4).readU32();
                        if (type === 1) { // SECBUFFER_DATA
                            var len = secBuffer.readU32();
                            var dataPtr = secBuffer.add(8).readPointer();
                            if (len > 0) {
                                console.log("\x1b[36m[SChannel] Decrypted (" + len + " bytes):\x1b[0m");
                                console.log(dumpMemory(dataPtr, len));
                            }
                        }
                    }
                } catch(e) {}
            }
        }
    });

    // =========================================================================
    // Part 2. OpenSSL (libssl-1_1-x64.dll)
    // =========================================================================
    var sslMod = "libssl-1_1-x64.dll";

    // SSL_read
    safeHook(sslMod, "SSL_read", {
        onEnter: function(args) { this.buf = args[1]; },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (len > 0) {
                console.log("\x1b[35m[OpenSSL] SSL_read (" + len + " bytes):\x1b[0m");
                console.log(dumpMemory(this.buf, len));
            }
        }
    });

    // SSL_write
    safeHook(sslMod, "SSL_write", {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0) {
                console.log("\x1b[32m[OpenSSL] SSL_write (" + len + " bytes):\x1b[0m");
                console.log(dumpMemory(args[1], len));
            }
        }
    });

    // SSL_read_ex (확장형)
    safeHook(sslMod, "SSL_read_ex", {
        onEnter: function(args) {
            this.buf = args[1];
            this.pReadBytes = args[3];
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 1 && !this.pReadBytes.isNull()) {
                    // size_t 읽기 (x64: readU64, x32: readU32)
                    // 안전하게 readPointer()로 읽어서 변환
                    var lenPtr = this.pReadBytes.readPointer(); 
                    var len = lenPtr.toInt32(); // 64비트여도 길이는 보통 2GB 안넘으므로 int32로 변환
                    
                    if (len > 0) {
                        console.log("\x1b[35m[OpenSSL] SSL_read_ex (" + len + " bytes):\x1b[0m");
                        console.log(dumpMemory(this.buf, len));
                    }
                }
            } catch(e) {}
        }
    });

    // SSL_write_ex (확장형)
    safeHook(sslMod, "SSL_write_ex", {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0) {
                console.log("\x1b[32m[OpenSSL] SSL_write_ex (" + len + " bytes):\x1b[0m");
                console.log(dumpMemory(args[1], len));
            }
        }
    });

})();

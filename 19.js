(function() {
    console.log("==================================================");
    console.log("[*] Starting Error-Proof All-in-One Monitor");
    console.log("==================================================");

    var hookedModules = {}; // 중복 방지

    // [1] 안전한 문자열 읽기 (호환성)
    function readSafeString(ptr) {
        if (!ptr || ptr.isNull()) return "(null)";
        try {
            if (typeof ptr.readUtf16String === 'function') return ptr.readUtf16String();
            if (typeof Memory.readUtf16String === 'function') return Memory.readUtf16String(ptr);
        } catch(e) {}
        return "(read error)";
    }

    // [2] 덤프 유틸리티
    function dumpMemory(ptr, length) {
        if (!ptr || ptr.isNull() || length <= 0) return "";
        try {
            var dumpLen = Math.min(length, 256);
            var buf = ptr.readByteArray(dumpLen);
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: dumpLen, header: false, ansi: false });
            }
            return "";
        } catch (e) { return ""; }
    }

    // [3] [핵심] 절대 에러나지 않는 주소 찾기 함수 (Safe Resolver)
    function resolveAddress(moduleName, funcName) {
        var ptr = null;
        try {
            // 1. 표준 방식 시도
            if (Module && typeof Module.findExportByName === 'function') {
                ptr = Module.findExportByName(moduleName, funcName);
            }
        } catch(e) {}

        if (ptr) return ptr;

        try {
            // 2. 모듈 객체를 통해 우회 시도
            if (Process && typeof Process.findModuleByName === 'function') {
                var m = Process.findModuleByName(moduleName);
                if (m && Module && typeof Module.findExportByName === 'function') {
                    ptr = Module.findExportByName(m.name, funcName);
                }
            }
        } catch(e) {}

        return ptr;
    }

    // [4] 안전한 후킹 적용 (Unified Hooker)
    function safeHook(moduleName, funcName, callbacks) {
        try {
            var ptr = resolveAddress(moduleName, funcName);
            if (ptr) {
                Interceptor.attach(ptr, callbacks);
                console.log("[+] Hooked: " + moduleName + "!" + funcName);
            }
        } catch(e) {
            // 에러가 나도 로그만 찍고 스크립트는 계속 실행됨
            console.log("[-] Hook Failed (" + funcName + "): " + e.message);
        }
    }

    // =========================================================================
    // Part A. 파일 시스템 감시 (File System)
    // =========================================================================
    function hookFileSystem() {
        if (hookedModules["FileSystem"]) return;
        
        // 1. CreateFileW
        safeHook("kernel32.dll", "CreateFileW", {
            onEnter: function(args) {
                this.path = readSafeString(args[0]);
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf("Windows") === -1 && this.path.indexOf("Font") === -1) {
                    // retval이 객체가 아닐 경우 대비
                    var handle = retval.toInt32 ? retval.toInt32() : retval;
                    var status = (handle === -1) ? "FAILED" : "SUCCESS";
                    console.log("\x1b[36m[FILE] Create: " + this.path + " -> " + status + "\x1b[0m");
                }
            }
        });

        // 2. DeleteFileW
        safeHook("kernel32.dll", "DeleteFileW", {
            onEnter: function(args) {
                console.log("\x1b[31m[FILE] DELETE: " + readSafeString(args[0]) + "\x1b[0m");
            }
        });

        // 3. MoveFileW
        safeHook("kernel32.dll", "MoveFileW", {
            onEnter: function(args) {
                console.log("\x1b[33m[FILE] MOVE: " + readSafeString(args[0]) + " -> " + readSafeString(args[1]) + "\x1b[0m");
            }
        });

        hookedModules["FileSystem"] = true;
    }

    // =========================================================================
    // Part B. SSL 감시 (SChannel + OpenSSL)
    // =========================================================================
    
    // Fuzzy Search Helper (이름 검색용)
    function findAddressFuzzy(moduleName, partialName) {
        try {
            var m = Process.findModuleByName(moduleName);
            if (!m) return null;
            
            // 모듈이 있으면 enumerateExports 시도
            if (Module && typeof Module.enumerateExports === 'function') {
                var exports = Module.enumerateExports(moduleName);
                for (var i = 0; i < exports.length; i++) {
                    if (exports[i].name.toLowerCase().indexOf(partialName.toLowerCase()) !== -1) {
                        return exports[i].address;
                    }
                }
            }
        } catch(e) {}
        return null;
    }

    function hookSChannel(modName) {
        // 정확한 이름이 없으면 Fuzzy 검색 시도
        var addr = resolveAddress(modName, "DecryptMessage");
        if (!addr) addr = findAddressFuzzy(modName, "DecryptMessage");

        if (addr) {
            console.log("[+] SChannel Found in: " + modName);
            Interceptor.attach(addr, {
                onEnter: function(args) { this.pMessage = args[1]; },
                onLeave: function(retval) {
                    var ret = retval.toInt32 ? retval.toInt32() : retval;
                    if (ret === 0 && this.pMessage) {
                        try {
                            var cBuffers = this.pMessage.add(4).readU32();
                            var pBuffers = this.pMessage.add(8).readPointer();
                            for (var i = 0; i < cBuffers; i++) {
                                var secBuffer = pBuffers.add(i * 16);
                                var type = secBuffer.add(4).readU32();
                                if (type === 1) { // SECBUFFER_DATA
                                    var len = secBuffer.readU32();
                                    var buf = secBuffer.add(8).readPointer();
                                    if (len > 0) {
                                        console.log("\x1b[36m[SChannel] Decrypt (" + len + " bytes):\x1b[0m");
                                        console.log(dumpMemory(buf, len));
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                }
            });
        }
    }

    function hookOpenSSL(modName) {
        console.log("[+] OpenSSL Found in: " + modName);
        var patterns = ["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"];

        patterns.forEach(function(pattern) {
            // 이름 검색으로 주소 찾기
            var addr = findAddressFuzzy(modName, pattern);
            if (!addr) return;

            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.funcName = pattern;
                    this.buf = args[1];
                    this.num = args[2].toInt32();
                    if (pattern.indexOf("_ex") !== -1) this.pReadBytes = args[3];
                },
                onLeave: function(retval) {
                    try {
                        var len = 0;
                        var ret = retval.toInt32 ? retval.toInt32() : retval;

                        if (this.funcName.indexOf("read") !== -1 && this.funcName.indexOf("_ex") === -1) len = ret;
                        else if (this.funcName.indexOf("write") !== -1) len = this.num;
                        else if (this.funcName.indexOf("_ex") !== -1 && ret === 1 && !this.pReadBytes.isNull()) {
                            len = this.pReadBytes.readPointer().toInt32();
                        }

                        if (len > 0) {
                            var color = this.funcName.indexOf("read") !== -1 ? "\x1b[35m" : "\x1b[32m";
                            console.log(color + "[OpenSSL] " + this.funcName + " (" + len + " bytes):\x1b[0m");
                            console.log(dumpMemory(this.buf, len));
                        }
                    } catch(e) {}
                }
            });
        });
    }

    // =========================================================================
    // 감시 루프 (Polling)
    // =========================================================================
    function poller() {
        // [파일 시스템] 안전하게 1회 실행
        hookFileSystem();

        // [SChannel] SspiCli.dll
        if (!hookedModules["SspiCli"]) {
            var m = null;
            try { m = Process.findModuleByName("SspiCli.dll"); } catch(e){}
            
            if (m) {
                hookSChannel(m.name);
                hookedModules["SspiCli"] = true;
            }
        }

        // [OpenSSL] libssl...
        if (!hookedModules["OpenSSL"]) {
            try {
                var modules = Process.enumerateModules();
                for (var i = 0; i < modules.length; i++) {
                    var name = modules[i].name.toLowerCase();
                    if (name.indexOf("libssl") !== -1) {
                        hookOpenSSL(modules[i].name);
                        hookedModules["OpenSSL"] = true;
                        break;
                    }
                }
            } catch(e) {}
        }
    }

    // 1초 간격 감시
    setInterval(poller, 1000);
    poller();

})();

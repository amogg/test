(function() {
    console.log("==================================================");
    console.log("[*] Starting All-in-One Monitor (File + SSL)");
    console.log("==================================================");

    var hookedModules = {}; // 중복 방지

    // [1] 유틸리티: 안전한 문자열 읽기 (호환성 끝판왕)
    function readSafeString(ptr) {
        if (ptr.isNull()) return "(null)";
        try {
            // 1. 최신 문법
            if (typeof ptr.readUtf16String === 'function') return ptr.readUtf16String();
            // 2. 구버전 문법
            if (typeof Memory.readUtf16String === 'function') return Memory.readUtf16String(ptr);
        } catch(e) {}
        return "(read error)";
    }

    // [2] 유틸리티: 덤프
    function dumpMemory(ptr, length) {
        if (ptr.isNull() || length <= 0) return "";
        try {
            var dumpLen = Math.min(length, 256);
            var buf = ptr.readByteArray(dumpLen);
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: dumpLen, header: false, ansi: false });
            }
            return "";
        } catch (e) { return ""; }
    }

    // [3] 유틸리티: 함수 주소 찾기 (이름 자동 검색 포함)
    function findExportAddress(moduleName, specificName, fuzzyMode) {
        var m = Process.findModuleByName(moduleName);
        if (!m) return null;

        // A. 정확한 이름으로 먼저 시도 (빠름)
        var addr = Module.findExportByName(moduleName, specificName);
        if (addr) return addr;

        // B. Fuzzy Mode: 이름이 포함된 함수 검색 (느리지만 확실함)
        if (fuzzyMode) {
            try {
                var exports = Module.enumerateExports(moduleName);
                for (var i = 0; i < exports.length; i++) {
                    if (exports[i].name.toLowerCase().indexOf(specificName.toLowerCase()) !== -1) {
                        console.log("    [Search] Found similar: " + exports[i].name);
                        return exports[i].address;
                    }
                }
            } catch(e) {}
        }
        return null;
    }

    // =========================================================================
    // Part A. 파일 시스템 후킹 (File System)
    // =========================================================================
    function hookFileSystem() {
        if (hookedModules["FileSystem"]) return;
        console.log("[*] Hooking File System APIs (Kernel32)...");

        // 1. CreateFileW (파일 생성/열기)
        var pCreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
        if (pCreateFileW) {
            Interceptor.attach(pCreateFileW, {
                onEnter: function(args) {
                    this.path = readSafeString(args[0]);
                },
                onLeave: function(retval) {
                    // 시스템 노이즈(Windows 폴더, 폰트 등) 필터링
                    if (this.path && this.path.indexOf("Windows") === -1 && this.path.indexOf("Font") === -1) {
                        var handle = retval.toInt32();
                        var status = (handle === -1) ? "FAILED" : "SUCCESS";
                        // 성공한 것만 보거나, 실패도 보거나 선택
                        console.log("\x1b[36m[FILE] Open/Create: " + this.path + " -> " + status + "\x1b[0m");
                    }
                }
            });
        }

        // 2. DeleteFileW (파일 삭제)
        var pDeleteFileW = Module.findExportByName("kernel32.dll", "DeleteFileW");
        if (pDeleteFileW) {
            Interceptor.attach(pDeleteFileW, {
                onEnter: function(args) {
                    var path = readSafeString(args[0]);
                    console.log("\x1b[31m[FILE] DELETE: " + path + "\x1b[0m");
                }
            });
        }

        // 3. MoveFileW (파일 이동/이름변경)
        var pMoveFileW = Module.findExportByName("kernel32.dll", "MoveFileW");
        if (pMoveFileW) {
            Interceptor.attach(pMoveFileW, {
                onEnter: function(args) {
                    var src = readSafeString(args[0]);
                    var dst = readSafeString(args[1]);
                    console.log("\x1b[33m[FILE] MOVE: " + src + " -> " + dst + "\x1b[0m");
                }
            });
        }
        
        hookedModules["FileSystem"] = true;
    }

    // =========================================================================
    // Part B. SSL 후킹 (SChannel & OpenSSL)
    // =========================================================================
    
    // B-1. SChannel
    function hookSChannel(modName) {
        console.log("[+] Module Detected: " + modName);
        var addr = findExportAddress(modName, "DecryptMessage", true); // Fuzzy Search
        
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) { this.pMessage = args[1]; },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.pMessage) {
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
                                        console.log("\x1b[36m[SChannel] Decrypted (" + len + " bytes):\x1b[0m");
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

    // B-2. OpenSSL
    function hookOpenSSL(modName) {
        console.log("[+] Module Detected: " + modName);
        var patterns = ["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"];

        patterns.forEach(function(pattern) {
            var addr = findExportAddress(modName, pattern, true); // Fuzzy Search
            if (!addr) return;

            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.funcName = pattern;
                    this.buf = args[1];
                    this.num = args[2].toInt32();
                    if (pattern.indexOf("_ex") !== -1) this.pReadBytes = args[3];
                },
                onLeave: function(retval) {
                    var len = 0;
                    try {
                        if (this.funcName.indexOf("read") !== -1 && this.funcName.indexOf("_ex") === -1) len = retval.toInt32();
                        else if (this.funcName.indexOf("write") !== -1) len = this.num;
                        else if (this.funcName.indexOf("_ex") !== -1 && retval.toInt32() === 1 && !this.pReadBytes.isNull()) {
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
    // Main Poller (감시 루프)
    // =========================================================================
    function poller() {
        // 1. 파일 시스템 (한 번만 실행하면 됨)
        hookFileSystem();

        // 2. SspiCli.dll (SChannel)
        if (!hookedModules["SspiCli"]) {
            var m = Process.findModuleByName("SspiCli.dll");
            if (m) {
                hookSChannel(m.name);
                hookedModules["SspiCli"] = true;
            }
        }

        // 3. OpenSSL (libssl...)
        if (!hookedModules["OpenSSL"]) {
            var modules = Process.enumerateModules();
            for (var i = 0; i < modules.length; i++) {
                var name = modules[i].name.toLowerCase();
                if (name.indexOf("libssl") !== -1) {
                    hookOpenSSL(modules[i].name);
                    hookedModules["OpenSSL"] = true;
                    break; 
                }
            }
        }
    }

    // 1초마다 새로운 모듈 로딩 체크
    setInterval(poller, 1000);
    poller(); // 즉시 실행

})();

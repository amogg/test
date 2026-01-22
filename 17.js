(function() {
    console.log("==================================================");
    console.log("[*] Waiting for SSL Modules to load (Lazy Hooking)...");
    console.log("==================================================");

    // [1] 이미 후킹했는지 체크하는 플래그
    var hookedModules = {};

    // [2] 덤프 유틸리티
    function dumpMemory(ptr, length) {
        if (ptr.isNull() || length <= 0) return "";
        try {
            var dumpLen = Math.min(length, 256);
            var buf = ptr.readByteArray(dumpLen);
            if (typeof hexdump === 'function') {
                var str = "\\n" + hexdump(buf, { offset: 0, length: dumpLen, header: false, ansi: false });
                if (length > dumpLen) str += "\\n... (truncated " + (length - dumpLen) + " bytes) ...";
                return str;
            }
            return "";
        } catch (e) { return "(dump error)"; }
    }

    // [3] 안전하게 함수 주소 찾기
    function getFuncAddr(moduleName, funcName) {
        try {
            return Module.findExportByName(moduleName, funcName);
        } catch(e) { return null; }
    }

    // =========================================================================
    // 후킹 로직 정의 (모듈이 로드된 후에 실행됨)
    // =========================================================================

    // A. Windows Native (SspiCli.dll) 후킹 로직
    function hookSChannel(modName) {
        console.log("[+] Target Module Detected: " + modName);
        
        var addr = getFuncAddr(modName, "DecryptMessage");
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
                                        console.log("\x1b[36m[SChannel] Decrypt (" + len + " bytes):\x1b[0m");
                                        console.log(dumpMemory(buf, len));
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                }
            });
            console.log("    -> Hooked DecryptMessage");
        } else {
            console.log("    [!] DecryptMessage not found in " + modName);
        }
    }

    // B. OpenSSL (libssl-1_1-x64.dll) 후킹 로직
    function hookOpenSSL(modName) {
        console.log("[+] Target Module Detected: " + modName);

        var funcs = ["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"];
        
        funcs.forEach(function(funcName) {
            var addr = getFuncAddr(modName, funcName);
            if (!addr) return;

            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.funcName = funcName;
                    this.buf = args[1];
                    this.num = args[2].toInt32(); // 일반 read/write용
                    
                    // _ex 함수는 args[3]이 readbytes 포인터
                    if (funcName.indexOf("_ex") !== -1) {
                         this.pReadBytes = args[3];
                    }
                },
                onLeave: function(retval) {
                    var len = 0;
                    var buf = this.buf;

                    // 1. SSL_read (리턴값이 길이)
                    if (this.funcName === "SSL_read") {
                        len = retval.toInt32();
                    }
                    // 2. SSL_write (onEnter에서 길이를 알 수 있지만 여기서도 확인 가능)
                    else if (this.funcName === "SSL_write") {
                        // Write는 보통 onEnter에서 찍는게 정확하지만 편의상
                        len = this.num; 
                    }
                    // 3. SSL_read_ex (리턴값 1 성공, 길이는 포인터에)
                    else if (this.funcName === "SSL_read_ex") {
                        if (retval.toInt32() === 1 && !this.pReadBytes.isNull()) {
                            len = this.pReadBytes.readPointer().toInt32();
                        }
                    }
                    // 4. SSL_write_ex
                    else if (this.funcName === "SSL_write_ex") {
                         len = this.num;
                    }

                    // 출력 (읽기: Magenta, 쓰기: Green)
                    if (len > 0) {
                        var color = this.funcName.indexOf("read") !== -1 ? "\x1b[35m" : "\x1b[32m";
                        console.log(color + "[OpenSSL] " + this.funcName + " (" + len + " bytes):\x1b[0m");
                        console.log(dumpMemory(buf, len));
                    }
                }
            });
            console.log("    -> Hooked " + funcName);
        });
    }

    // =========================================================================
    // [핵심] 감시 루프 (Polling)
    // =========================================================================
    function checkForModules() {
        // 1. SspiCli.dll 감시
        if (!hookedModules["SspiCli.dll"]) {
            var m = Process.findModuleByName("SspiCli.dll");
            if (m) {
                hookSChannel(m.name);
                hookedModules["SspiCli.dll"] = true;
            }
        }

        // 2. libssl-1_1-x64.dll 감시 (대소문자 무시를 위해 전체 검색)
        if (!hookedModules["libssl"]) {
            var modules = Process.enumerateModules();
            for (var i = 0; i < modules.length; i++) {
                var name = modules[i].name.toLowerCase();
                // 스캐너에서 찾았던 그 이름 패턴
                if (name.indexOf("libssl-1_1-x64") !== -1) {
                    hookOpenSSL(modules[i].name);
                    hookedModules["libssl"] = true;
                    break;
                }
            }
        }
    }

    // 1초(1000ms)마다 모듈이 로드되었는지 확인합니다.
    setInterval(checkForModules, 1000);
    
    // 시작 시 한 번 즉시 실행
    checkForModules();

})();

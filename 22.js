(function() {
    // =========================================================================
    // [0] 초기화 및 환경 설정 (x64)
    // =========================================================================
    var ptrSize = Process.pointerSize;
    if (ptrSize !== 8) {
        send("[!] Warning: This script is optimized for x64 (8 bytes), but process is " + ptrSize + " bytes.");
    }

    send("==================================================");
    send("[*] Starting STABLE Monitor (Crash Proof)");
    send("[*] Architecture: x64");
    send("==================================================");

    // =========================================================================
    // [1] 절대 죽지 않는 유틸리티 함수들 (Defensive Utils)
    // =========================================================================

    // 문자열 읽기: 메서드 직접 호출 대신 Memory 글로벌 객체 사용 시도
    function safeReadString(ptr) {
        if (!ptr) return "(null)";
        try {
            // 1순위: Memory 객체 사용 (가장 안전)
            if (Memory && Memory.readUtf16String) {
                return Memory.readUtf16String(ptr);
            }
            // 2순위: 객체 메서드
            if (ptr.readUtf16String) {
                return ptr.readUtf16String();
            }
        } catch(e) {
            // 읽기 권한 없음 등의 에러 무시
        }
        return "(read error)";
    }

    // 메모리 덤프: hexdump가 없어도 죽지 않음
    function safeDump(ptr, len) {
        if (!ptr || len <= 0) return "";
        try {
            var buf = ptr.readByteArray(Math.min(len, 256));
            if (hexdump) {
                return "\n" + hexdump(buf, { offset: 0, length: Math.min(len, 256), header: false, ansi: false });
            }
        } catch(e) {}
        return " (dump failed)";
    }

    // 함수 주소 찾기: Module이 없거나 함수가 없어도 null 반환
    function getAddr(modName, funcName) {
        try {
            return Module.findExportByName(modName, funcName);
        } catch(e) {
            return null;
        }
    }

    // 유사 이름 찾기 (Fuzzy Search): 모듈 내부를 뒤짐
    function getAddrFuzzy(modName, partialName) {
        try {
            var m = Process.findModuleByName(modName);
            if (!m) return null;
            
            // Module.enumerateExports 사용 (없으면 catch로 이동)
            var exports = Module.enumerateExports(modName);
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name.toLowerCase().indexOf(partialName.toLowerCase()) !== -1) {
                    return exports[i].address;
                }
            }
        } catch(e) {}
        return null;
    }

    // =========================================================================
    // [2] 후킹 로직 (try-catch로 개별 격리)
    // =========================================================================

    // 2-1. SChannel (Windows Native SSL)
    function hookSChannel(modName) {
        // 정확한 이름 시도 -> 없으면 검색
        var addr = getAddr(modName, "DecryptMessage");
        if (!addr) addr = getAddrFuzzy(modName, "DecryptMessage");

        if (addr) {
            send("[+] SChannel Found in: " + modName);
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) { this.msg = args[1]; },
                    onLeave: function(retval) {
                        try {
                            // retval이 객체인지 숫자인지 체크 안하고 바로 toInt32 시도하면 에러날 수 있음
                            var ret = retval.toInt32();
                            if (ret === 0 && this.msg) {
                                // x64 오프셋 하드코딩: 
                                // ulVersion(4) + cBuffers(4) + pBuffers(8)
                                var cBuffers = this.msg.add(4).readU32();
                                var pBuffers = this.msg.add(8).readPointer(); 

                                for (var i = 0; i < cBuffers; i++) {
                                    // SecBuffer (x64): cbBuffer(4) + BufferType(4) + pvBuffer(8) = 16 bytes
                                    var bufStruct = pBuffers.add(i * 16);
                                    var type = bufStruct.add(4).readU32();
                                    
                                    if (type === 1) { // SECBUFFER_DATA
                                        var len = bufStruct.readU32();
                                        var data = bufStruct.add(8).readPointer();
                                        if (len > 0) {
                                            send("\x1b[36m[SChannel] Decrypt (" + len + " bytes):\x1b[0m" + safeDump(data, len));
                                        }
                                    }
                                }
                            }
                        } catch(e) { /* 파싱 에러 무시 */ }
                    }
                });
            } catch(e) { send("[-] Failed to attach SChannel: " + e.message); }
        }
    }

    // 2-2. OpenSSL (libssl)
    function hookOpenSSL(modName) {
        send("[+] OpenSSL Found in: " + modName);
        var targets = ["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"];

        targets.forEach(function(func) {
            var addr = getAddrFuzzy(modName, func);
            if (!addr) return;

            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        this.func = func;
                        this.buf = args[1];
                        this.num = args[2].toInt32();
                        if (func.indexOf("_ex") !== -1) this.pLen = args[3];
                    },
                    onLeave: function(retval) {
                        try {
                            var len = 0;
                            var ret = retval.toInt32();

                            if (this.func.indexOf("read") !== -1 && this.func.indexOf("_ex") === -1) {
                                len = ret; // SSL_read
                            } else if (this.func.indexOf("write") !== -1) {
                                len = this.num; // SSL_write
                            } else if (this.func.indexOf("_ex") !== -1 && ret === 1) {
                                // SSL_read_ex: 성공시 pLen에서 길이 읽기 (x64 = readU64)
                                if (this.pLen && !this.pLen.isNull()) {
                                    // toNumber()를 써서 안전하게 JS 숫자로 변환
                                    len = this.pLen.readU64().toNumber();
                                }
                            }

                            if (len > 0) {
                                var color = this.func.indexOf("read") !== -1 ? "\x1b[35m" : "\x1b[32m";
                                send(color + "[OpenSSL] " + this.func + " (" + len + " bytes):\x1b[0m" + safeDump(this.buf, len));
                            }
                        } catch(e) {}
                    }
                });
            } catch(e) {}
        });
    }

    // 2-3. FileSystem
    var fsDone = false;
    function hookFile() {
        if (fsDone) return;
        var addr = getAddr("kernel32.dll", "CreateFileW");
        if (addr) {
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        this.path = safeReadString(args[0]);
                    },
                    onLeave: function(retval) {
                        // 중요하지 않은 경로 필터링
                        if (this.path.indexOf("Windows") === -1 && this.path.indexOf("Font") === -1 && this.path.indexOf(".dll") === -1) {
                            send("\x1b[36m[FILE] Create: " + this.path + "\x1b[0m");
                        }
                    }
                });
                fsDone = true;
            } catch(e) {}
        }
    }

    // =========================================================================
    // [3] Poller Loop (Lazy Loading 대응)
    // =========================================================================
    var hooked = {};

    function poll() {
        // File System
        hookFile();

        // SChannel
        if (!hooked["sspi"]) {
            try {
                var m = Process.findModuleByName("SspiCli.dll");
                if (m) {
                    hookSChannel(m.name);
                    hooked["sspi"] = true;
                }
            } catch(e) {}
        }

        // OpenSSL
        if (!hooked["openssl"]) {
            try {
                var modules = Process.enumerateModules();
                for (var i = 0; i < modules.length; i++) {
                    var name = modules[i].name.toLowerCase();
                    if (name.indexOf("libssl") !== -1) {
                        hookOpenSSL(modules[i].name);
                        hooked["openssl"] = true;
                        break;
                    }
                }
            } catch(e) {}
        }
    }

    // 1초마다 실행
    setInterval(poll, 1000);
    poll(); // 즉시 실행
})();

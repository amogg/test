(function() {
    console.log("==================================================");
    console.log("[*] Starting Hybrid SSL Hooking (SspiCli + OpenSSL)");
    console.log("==================================================");

    // [1] 유틸리티: 메모리 덤프 (Hex + ASCII)
    function dumpMemory(ptr, length) {
        if (ptr.isNull() || length <= 0) return "";
        try {
            // 너무 길면 256바이트만 잘라서 보여줌
            var dumpLen = Math.min(length, 256);
            var buf = ptr.readByteArray(dumpLen);
            var str = "\\n" + hexdump(buf, { offset: 0, length: dumpLen, header: false, ansi: false });
            if (length > dumpLen) str += "\\n... (truncated " + (length - dumpLen) + " bytes) ...";
            return str;
        } catch (e) { return "(dump error)"; }
    }

    // [2] 유틸리티: 안전한 후킹 헬퍼
    function safeHook(moduleName, funcName, callbacks) {
        var ptr = Module.findExportByName(moduleName, funcName);
        if (!ptr) {
            // 혹시라도 모듈 이름이 다를 수 있으니 모듈 객체에서도 찾아봄
            var m = Process.findModuleByName(moduleName);
            if (m) ptr = Module.findExportByName(m.name, funcName);
        }

        if (ptr) {
            try {
                Interceptor.attach(ptr, callbacks);
                console.log("[+] Hooked: " + moduleName + "!" + funcName);
            } catch(e) { console.log("[-] Hook Error (" + funcName + "): " + e.message); }
        } else {
            console.log("[-] Not Found: " + moduleName + "!" + funcName);
        }
    }

    // =========================================================================
    // Part 1. Windows Native SSL (SspiCli.dll / DecryptMessage)
    // =========================================================================
    // SChannel이 패킷을 복호화한 직후(onLeave) 데이터를 가로챕니다.
    
    safeHook("SspiCli.dll", "DecryptMessage", {
        onEnter: function(args) {
            // args[1]: PSecBufferDesc (복호화할 데이터 버퍼 리스트)
            this.pMessage = args[1];
        },
        onLeave: function(retval) {
            // SEC_E_OK (0) 인 경우만 성공
            if (retval.toInt32() === 0 && this.pMessage) {
                // SecBufferDesc 구조체 파싱
                // ULONG ulVersion;
                // ULONG cBuffers; (버퍼 개수)
                // PSecBuffer pBuffers; (버퍼 배열 포인터)
                var cBuffers = this.pMessage.add(4).readU32(); // 두 번째 4바이트가 개수
                var pBuffers = this.pMessage.add(8).readPointer(); // 세 번째가 포인터 (x64)
                // 32비트라면 add(8)이 아니라 add(8) 위치가 다를 수 있음 (여기선 x64 기준)

                // 버퍼 배열을 순회하며 SECBUFFER_DATA (Type 1) 찾기
                for (var i = 0; i < cBuffers; i++) {
                    // SecBuffer 구조체 크기 = 4(cbBuffer) + 4(BufferType) + 8(pvBuffer) = 16 bytes (x64)
                    var secBuffer = pBuffers.add(i * 16); 
                    var type = secBuffer.add(4).readU32();
                    
                    if (type === 1) { // SECBUFFER_DATA (실제 데이터)
                        var len = secBuffer.readU32();
                        var dataPtr = secBuffer.add(8).readPointer();
                        if (len > 0) {
                            console.log("\x1b[36m[SChannel] Decrypted Data (" + len + " bytes):\x1b[0m");
                            console.log(dumpMemory(dataPtr, len));
                        }
                    }
                }
            }
        }
    });

    // =========================================================================
    // Part 2. OpenSSL (libssl-1_1-x64.dll) - Standard & Extended (_ex)
    // =========================================================================
    
    var sslMod = "libssl-1_1-x64.dll";

    // 2-1. SSL_write (보내는 데이터 - 암호화 전)
    // int SSL_write(SSL *ssl, const void *buf, int num);
    safeHook(sslMod, "SSL_write", {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0) {
                console.log("\x1b[32m[OpenSSL] SSL_write (" + len + " bytes):\x1b[0m");
                console.log(dumpMemory(args[1], len));
            }
        }
    });

    // 2-2. SSL_write_ex (확장형)
    // int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
    safeHook(sslMod, "SSL_write_ex", {
        onEnter: function(args) {
            var len = args[2].toInt32(); // size_t num
            if (len > 0) {
                console.log("\x1b[32m[OpenSSL] SSL_write_ex (" + len + " bytes):\x1b[0m");
                console.log(dumpMemory(args[1], len));
            }
        }
    });

    // 2-3. SSL_read (받는 데이터 - 복호화 후)
    // int SSL_read(SSL *ssl, void *buf, int num);
    safeHook(sslMod, "SSL_read", {
        onEnter: function(args) {
            this.buf = args[1]; // 버퍼 주소 저장
        },
        onLeave: function(retval) {
            var len = retval.toInt32(); // 읽은 바이트 수 리턴
            if (len > 0) {
                console.log("\x1b[35m[OpenSSL] SSL_read (" + len + " bytes):\x1b[0m");
                console.log(dumpMemory(this.buf, len));
            }
        }
    });

    // 2-4. SSL_read_ex (확장형 - 가장 중요!)
    // int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes);
    // 리턴값은 성공(1)/실패(0)이고, 실제 읽은 길이는 4번째 인자 포인터에 담김
    safeHook(sslMod, "SSL_read_ex", {
        onEnter: function(args) {
            this.buf = args[1];       // 데이터를 담을 버퍼
            this.pReadBytes = args[3]; // 실제 읽은 길이가 저장될 주소
        },
        onLeave: function(retval) {
            // retval이 1이면 성공
            if (retval.toInt32() === 1 && !this.pReadBytes.isNull()) {
                var len = this.pReadBytes.readU64().toNumber(); // size_t (x64니까 8바이트 읽기)
                if (len > 0) {
                    console.log("\x1b[35m[OpenSSL] SSL_read_ex (" + len + " bytes):\x1b[0m");
                    console.log(dumpMemory(this.buf, len));
                }
            }
        }
    });

})();

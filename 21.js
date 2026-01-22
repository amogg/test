(function() {
    console.log("==================================================");
    console.log("[*] SSL DEBUG MODE STARTED (Verbose)");
    console.log("[*] Process Arch: " + Process.arch); // x64인지 ia32인지 확인
    console.log("[*] Pointer Size: " + Process.pointerSize);
    console.log("==================================================");

    // [1] 안전한 메모리 읽기/덤프
    function dumpMemory(ptr, length) {
        if (!ptr || ptr.isNull() || length <= 0) return "[Empty]";
        try {
            var dumpLen = Math.min(length, 128); // 128바이트만
            var buf = ptr.readByteArray(dumpLen);
            if (typeof hexdump === 'function') {
                return hexdump(buf, { offset: 0, length: dumpLen, header: false, ansi: false });
            }
            return "[No hexdump function]";
        } catch (e) { return "[Dump Error: " + e.message + "]"; }
    }

    // [2] 주소 해결사
    function resolveAddress(modName, funcName) {
        var ptr = Module.findExportByName(modName, funcName);
        if (!ptr) {
            try {
                var m = Process.findModuleByName(modName);
                if (m) ptr = Module.findExportByName(m.name, funcName);
            } catch(e) {}
        }
        return ptr;
    }

    // =========================================================================
    // Part 1. OpenSSL 디버깅 (모든 호출 기록)
    // =========================================================================
    function hookOpenSSL(modName) {
        console.log("[+] Hooking OpenSSL in: " + modName);
        
        // 1. SSL_read (기본)
        var pRead = resolveAddress(modName, "SSL_read");
        if (pRead) {
            Interceptor.attach(pRead, {
                onEnter: function(args) {
                    this.buf = args[1];
                    this.num = args[2].toInt32();
                    // 호출 시점 로그 (너무 시끄러우면 주석 처리)
                    // console.log("[SSL_read] Enter. Request Size: " + this.num);
                },
                onLeave: function(retval) {
                    var ret = retval.toInt32();
                    if (ret > 0) {
                        console.log("\x1b[32m[SSL_read] SUCCESS (" + ret + " bytes)\x1b[0m");
                        console.log(dumpMemory(this.buf, ret));
                    } else {
                        // 실패/대기 상태도 로그로 확인
                        // ret 0: 연결 종료, ret < 0: 에러/WANT_READ
                        // console.log("[SSL_read] Returns: " + ret + " (No Data)"); 
                    }
                }
            });
        }

        // 2. SSL_read_ex (확장형 - 64비트/32비트 포인터 처리 주의)
        var pReadEx = resolveAddress(modName, "SSL_read_ex");
        if (pReadEx) {
            Interceptor.attach(pReadEx, {
                onEnter: function(args) {
                    this.buf = args[1];
                    this.pReadBytes = args[3];
                },
                onLeave: function(retval) {
                    var ret = retval.toInt32(); // 1=성공, 0=실패
                    
                    if (ret === 1) {
                        var len = 0;
                        // 아키텍처에 맞게 길이 읽기
                        if (Process.pointerSize === 8) len = this.pReadBytes.readU64().toNumber();
                        else len = this.pReadBytes.readU32();

                        console.log("\x1b[32m[SSL_read_ex] SUCCESS (" + len + " bytes)\x1b[0m");
                        console.log(dumpMemory(this.buf, len));
                    } else {
                        // console.log("[SSL_read_ex] Failed/Pending. Ret: " + ret);
                    }
                }
            });
        }
    }

    // =========================================================================
    // Part 2. SChannel (SspiCli) 디버깅 (구조체 오프셋 정밀 분석)
    // =========================================================================
    function hookSChannel(modName) {
        console.log("[+] Hooking SChannel in: " + modName);
        var pDecrypt = resolveAddress(modName, "DecryptMessage");
        
        if (pDecrypt) {
            Interceptor.attach(pDecrypt, {
                onEnter: function(args) { 
                    this.pMessage = args[1]; // SecBufferDesc 포인터
                },
                onLeave: function(retval) {
                    var ret = retval.toInt32();
                    // console.log("[DecryptMessage] Returns: " + ret + " (0 is Success)");

                    if (ret === 0 && this.pMessage) {
                        try {
                            // 구조체 오프셋 자동 계산 (32bit vs 64bit)
                            // SecBufferDesc: { ulVersion, cBuffers, pBuffers }
                            var offset_pBuffers = (Process.pointerSize === 8) ? 8 : 8; // 보통 둘다 8 (4+4)
                            
                            var cBuffers = this.pMessage.add(4).readU32();
                            var pBuffers = this.pMessage.add(offset_pBuffers).readPointer();
                            
                            // SecBuffer Size: 32bit(12bytes), 64bit(16bytes)
                            var secBufSize = (Process.pointerSize === 8) ? 16 : 12;

                            // console.log("   -> cBuffers: " + cBuffers);

                            for (var i = 0; i < cBuffers; i++) {
                                var currentBuf = pBuffers.add(i * secBufSize);
                                
                                // SecBuffer: { cbBuffer, BufferType, pvBuffer }
                                var cbBuffer = currentBuf.readU32();
                                var type = currentBuf.add(4).readU32();
                                var pvBuffer = currentBuf.add(8).readPointer(); // 32bit여도 offset 8이 일반적

                                // BufferType 1 = SECBUFFER_DATA (복호화된 데이터)
                                if (type === 1 && cbBuffer > 0) {
                                    console.log("\x1b[36m[SChannel] DecryptMessage Found DATA (" + cbBuffer + " bytes)\x1b[0m");
                                    console.log(dumpMemory(pvBuffer, cbBuffer));
                                } else {
                                    // 데이터가 아닌 버퍼 타입도 로그 찍어봄 (디버그용)
                                    // console.log("   -> Buf[" + i + "] Type: " + type + ", Size: " + cbBuffer);
                                }
                            }
                        } catch(e) {
                            console.log("[!] SChannel Parse Error: " + e.message);
                        }
                    }
                }
            });
        }
    }

    // =========================================================================
    // Poller
    // =========================================================================
    var hooked = {};
    setInterval(function(){
        // OpenSSL
        if (!hooked["openssl"]) {
            var modules = Process.enumerateModules();
            for (var i=0; i<modules.length; i++) {
                if (modules[i].name.toLowerCase().indexOf("libssl") !== -1) {
                    hookOpenSSL(modules[i].name);
                    hooked["openssl"] = true;
                    break;
                }
            }
        }
        // SChannel
        if (!hooked["sspi"]) {
            var m = Process.findModuleByName("SspiCli.dll");
            if (m) {
                hookSChannel(m.name);
                hooked["sspi"] = true;
            }
        }
    }, 1000);

})();

(function() {
    console.log("==================================================");
    console.log("[*] Advapi32.dll CryptoAPI Hooking");
    console.log("[*] Targets: CryptEncrypt (Send), CryptDecrypt (Recv)");
    console.log("==================================================");

    // [1] 안전한 덤프 함수
    function safeDump(ptr, len) {
        if (!ptr || len <= 0) return "";
        try {
            if (ptr.toString() === "0x0") return "";
            var buf = Memory.readByteArray(ptr, Math.min(len, 256));
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: Math.min(len, 256), header: false, ansi: false });
            }
            return " [Hexdump missing]";
        } catch(e) { return ""; }
    }

    // [2] Advapi32.dll 모듈 찾기
    var modName = "Advapi32.dll";
    var m = Process.findModuleByName(modName);
    
    // 만약 이름으로 못 찾으면 경로 검색 (대소문자 이슈 대비)
    if (!m) {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            if (modules[i].name.toLowerCase() === "advapi32.dll") {
                m = modules[i];
                modName = modules[i].name;
                break;
            }
        }
    }

    if (!m) {
        console.log("[-] Advapi32.dll is not loaded.");
        return;
    }

    // [3] CryptEncrypt 후킹 (평문 -> 암호문)
    // BOOL CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    // 핵심: pbData (입력 시 평문이 들어있음)
    var pEncrypt = Module.findExportByName(modName, "CryptEncrypt");
    if (pEncrypt) {
        Interceptor.attach(pEncrypt, {
            onEnter: function(args) {
                try {
                    // 5번째 인자: pbData (데이터 포인터)
                    // 6번째 인자: pdwDataLen (데이터 길이의 포인터)
                    this.pbData = args[4];
                    this.pDataLen = args[5];
                    
                    if (!this.pDataLen.isNull()) {
                        var len = this.pDataLen.readU32();
                        if (len > 0) {
                            console.log("\x1b[32m[CAPI] CryptEncrypt (Plain): \x1b[0m" + safeDump(this.pbData, len));
                        }
                    }
                } catch(e) {}
            }
        });
        console.log("[+] Hooked CryptEncrypt");
    }

    // [4] CryptDecrypt 후킹 (암호문 -> 평문)
    // BOOL CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    // 핵심: 함수가 성공하고 리턴된 후(onLeave) pbData에 평문이 담김
    var pDecrypt = Module.findExportByName(modName, "CryptDecrypt");
    if (pDecrypt) {
        Interceptor.attach(pDecrypt, {
            onEnter: function(args) {
                this.pbData = args[4];
                this.pDataLen = args[5];
            },
            onLeave: function(retval) {
                try {
                    // retval != 0 (TRUE) 이어야 성공
                    if (retval.toInt32() !== 0 && !this.pDataLen.isNull()) {
                        var len = this.pDataLen.readU32();
                        if (len > 0) {
                            console.log("\x1b[35m[CAPI] CryptDecrypt (Plain): \x1b[0m" + safeDump(this.pbData, len));
                        }
                    }
                } catch(e) {}
            }
        });
        console.log("[+] Hooked CryptDecrypt");
    }

    // [5] (보너스) 해시 함수도 체크 (CryptHashData)
    // 로그인 시 비밀번호를 바로 암호화하지 않고 해싱만 해서 보낼 수도 있음
    var pHash = Module.findExportByName(modName, "CryptHashData");
    if (pHash) {
        Interceptor.attach(pHash, {
            onEnter: function(args) {
                try {
                    var len = args[2].toInt32();
                    if (len > 0) {
                        console.log("\x1b[33m[CAPI] CryptHashData (Input): \x1b[0m" + safeDump(args[1], len));
                    }
                } catch(e) {}
            }
        });
        console.log("[+] Hooked CryptHashData");
    }

})();

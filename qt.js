(function() {
    console.log("==================================================");
    console.log("[*] Qt SSL Hooking (Targeting QSslSocket)");
    console.log("[*] Goal: Capture Unencrypted Data");
    console.log("==================================================");

    function safeDump(ptr, len) {
        if (!ptr || len <= 0) return "";
        try {
            // ptr이 0인지 안전하게 확인
            if (ptr.toString() === "0x0") return "";
            
            var buf = Memory.readByteArray(ptr, Math.min(len, 256));
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: Math.min(len, 256), header: false, ansi: false });
            }
            return " [Hexdump missing]";
        } catch(e) { return ""; }
    }

    function hookQtNetwork() {
        var qtModule = null;
        
        // 1. Qt Network 모듈 찾기 (Qt5 또는 Qt6)
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var mName = modules[i].name;
            if (mName.toLowerCase().indexOf("qt") !== -1 && mName.toLowerCase().indexOf("network") !== -1) {
                qtModule = mName;
                console.log("[+] Found Qt Network Module: " + mName);
                break;
            }
        }

        if (!qtModule) {
            console.log("[-] Qt Network module not found. (Is it statically linked?)");
            return;
        }

        // 2. QSslSocket 심볼 검색 (Export Table)
        var exports = Module.enumerateExports(qtModule);
        var hookCount = 0;

        for (var i = 0; i < exports.length; i++) {
            var exp = exports[i];
            var name = exp.name;
            
            // Qt 함수 이름(맹글링)에 QSslSocket이 포함된 것 찾기
            if (name.indexOf("QSslSocket") !== -1) {
                
                // [보낼 때] writeData(data, len)
                // 암호화 되기 '직전'의 평문 데이터
                if (name.indexOf("writeData") !== -1) {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                try {
                                    // Calling Convention 자동 감지되지만, 아키텍처별로 안전하게 처리
                                    var len = 0;
                                    var buf = null;

                                    if (Process.pointerSize === 8) { // x64
                                        // RCX: this, RDX: buf, R8: len
                                        buf = args[1];
                                        len = args[2].toInt32();
                                    } else { // x86
                                        // Stack: this, buf, len
                                        buf = args[0];
                                        len = args[1].toInt32();
                                    }

                                    if (len > 0) {
                                        console.log("\x1b[32m[Qt-SSL] Send (Plain): \x1b[0m" + safeDump(buf, len));
                                    }
                                } catch(e) {}
                            }
                        });
                        hookCount++;
                        // console.log("    -> Hooked Write: " + name); // 너무 많으면 주석
                    } catch(e) {}
                }

                // [받을 때] readData(data, maxlen)
                // 복호화 된 '직후'의 평문 데이터는 onLeave에서 확인
                // 주의: Qt 내부 구현상 readData보다는 'plainText' 관련 신호를 잡는게 좋지만,
                // 바이너리 레벨에선 readData가 가장 보편적입니다.
                else if (name.indexOf("readData") !== -1) {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                if (Process.pointerSize === 8) this.buf = args[1]; // x64
                                else this.buf = args[0]; // x86
                            },
                            onLeave: function(retval) {
                                try {
                                    var len = retval.toInt32();
                                    if (len > 0) {
                                        console.log("\x1b[35m[Qt-SSL] Recv (Plain): \x1b[0m" + safeDump(this.buf, len));
                                    }
                                } catch(e) {}
                            }
                        });
                        hookCount++;
                    } catch(e) {}
                }
            }
        }

        if (hookCount > 0) {
            console.log("[+] Successfully hooked " + hookCount + " QSslSocket functions.");
        } else {
            console.log("[-] Symbols found but failed to hook, or symbols stripped.");
        }
    }

    // 1초 뒤 실행 (모듈 로딩 대기)
    setTimeout(hookQtNetwork, 1000);

})();

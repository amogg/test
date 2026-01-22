import frida
import sys
import time

# 감시할 프로세스 접두사 (예: aaa_)
TARGET_PREFIX = "aaa_"
attached_pids = set()

JS_CODE = """
(function() {
    // =========================================================================
    // [1] 절대 에러나지 않는 헬퍼 함수 (메서드 호출 최소화)
    // =========================================================================
    
    // 로그 전송
    function sendLog(tag, msg) {
        send("[" + tag + "] " + msg);
    }

    // 문자열 읽기 (ptr.isNull() 제거 -> 값 비교로 대체)
    function safeReadString(ptr) {
        try {
            if (!ptr) return "(null)"; // null 체크
            
            // ptr이 0인지 확인 (메서드 대신 문자열 변환이나 산술연산 사용)
            if (ptr.toString() === "0x0") return "(null)";

            // Memory 객체 사용
            return Memory.readUtf16String(ptr);
        } catch(e) {
            return "(read error)";
        }
    }

    // 메모리 덤프
    function safeDump(ptr, len) {
        try {
            if (!ptr || len <= 0) return "";
            if (ptr.toString() === "0x0") return "";
            
            var buf = Memory.readByteArray(ptr, Math.min(len, 128));
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: Math.min(len, 128), header: false, ansi: false });
            }
            return " [Hexdump missing]";
        } catch(e) { return ""; }
    }

    // 함수 주소 찾기 (에러 무시)
    function getAddr(mod, func) {
        try {
            return Module.findExportByName(mod, func);
        } catch(e) { return null; }
    }

    // =========================================================================
    // [2] 파일 시스템 후킹 (HookFile) - 에러 수정됨
    // =========================================================================
    function hookFile() {
        // CreateFileW
        var pCreate = getAddr("kernel32.dll", "CreateFileW");
        if (pCreate) {
            try {
                Interceptor.attach(pCreate, {
                    onEnter: function(args) {
                        try {
                            // 여기서 args[0]이 NativePointer가 아니어도 죽지 않음
                            this.path = safeReadString(args[0]);
                        } catch(e) { this.path = "(arg error)"; }
                    },
                    onLeave: function(retval) {
                        try {
                            if (this.path && this.path.indexOf("Windows") === -1 && this.path.indexOf(".dll") === -1) {
                                sendLog("FILE", "Create: " + this.path);
                            }
                        } catch(e) {}
                    }
                });
            } catch(e) { sendLog("ERR", "CreateFile Hook Failed: " + e.message); }
        }

        // WriteFile
        var pWrite = getAddr("kernel32.dll", "WriteFile");
        if (pWrite) {
            try {
                Interceptor.attach(pWrite, {
                    onEnter: function(args) {
                        try {
                            // args[2] = size
                            this.len = args[2].toInt32();
                            // args[1] = buffer
                            this.buf = args[1];
                        } catch(e) {}
                    },
                    onLeave: function(retval) {
                        // 필요시 주석 해제 (로그 너무 많을 수 있음)
                        /*
                        if (this.len > 0) {
                            sendLog("FILE", "Write (" + this.len + " bytes)");
                        }
                        */
                    }
                });
            } catch(e) {}
        }
    }

    // =========================================================================
    // [3] SSL 후킹 (Native + OpenSSL)
    // =========================================================================
    
    // SChannel (SspiCli.dll)
    function hookSChannel(modName) {
        var pDecrypt = getAddr(modName, "DecryptMessage");
        if (!pDecrypt) {
            // 없으면 검색
            try {
                var exports = Module.enumerateExports(modName);
                for(var i=0; i<exports.length; i++) {
                    if(exports[i].name.indexOf("DecryptMessage") !== -1) {
                        pDecrypt = exports[i].address;
                        break;
                    }
                }
            } catch(e){}
        }

        if (pDecrypt) {
            sendLog("SYS", "Hooking SChannel: " + modName);
            Interceptor.attach(pDecrypt, {
                onEnter: function(args) { this.msg = args[1]; },
                onLeave: function(retval) {
                    try {
                        if (retval.toInt32() === 0 && this.msg) {
                            // x64 구조체 하드코딩
                            var cBufs = this.msg.add(4).readU32();
                            var pBufs = this.msg.add(8).readPointer();
                            
                            for (var i = 0; i < cBufs; i++) {
                                var cur = pBufs.add(i * 16);
                                var type = cur.add(4).readU32();
                                if (type === 1) { // DATA
                                    var len = cur.readU32();
                                    var buf = cur.add(8).readPointer();
                                    if (len > 0) {
                                        sendLog("\\x1b[36mSChannel\\x1b[0m", "Decrypt (" + len + " bytes)" + safeDump(buf, len));
                                    }
                                }
                            }
                        }
                    } catch(e) {}
                }
            });
        }
    }

    // OpenSSL (libssl)
    function hookOpenSSL(modName) {
        sendLog("SYS", "Hooking OpenSSL: " + modName);
        
        // 검색 헬퍼
        function findAndHook(pattern, callback) {
            try {
                var exports = Module.enumerateExports(modName);
                for(var i=0; i<exports.length; i++) {
                    var name = exports[i].name;
                    if(name.indexOf(pattern) !== -1 && name.indexOf("_ex") === -1) {
                        // _ex 제외하고 기본 함수 먼저
                        Interceptor.attach(exports[i].address, callback);
                        return; 
                    }
                }
            } catch(e){}
        }

        // 1. SSL_read
        findAndHook("SSL_read", {
            onEnter: function(args) { this.buf = args[1]; },
            onLeave: function(retval) {
                try {
                    var len = retval.toInt32();
                    if(len > 0) {
                        sendLog("\\x1b[32mOpenSSL\\x1b[0m", "Read (" + len + " bytes)" + safeDump(this.buf, len));
                    }
                } catch(e){}
            }
        });

        // 2. SSL_write
        findAndHook("SSL_write", {
            onEnter: function(args) {
                try {
                    var len = args[2].toInt32();
                    if(len > 0) {
                        sendLog("\\x1b[33mOpenSSL\\x1b[0m", "Write (" + len + " bytes)" + safeDump(args[1], len));
                    }
                } catch(e){}
            }
        });
        
        // 3. SSL_read_ex (별도 검색)
        try {
            var exports = Module.enumerateExports(modName);
            for(var i=0; i<exports.length; i++) {
                if(exports[i].name.indexOf("SSL_read_ex") !== -1) {
                    Interceptor.attach(exports[i].address, {
                        onEnter: function(args) { this.buf = args[1]; this.pLen = args[3]; },
                        onLeave: function(retval) {
                            try {
                                if(retval.toInt32() === 1 && this.pLen) {
                                    var len = this.pLen.readU64().toNumber();
                                    if(len > 0) {
                                        sendLog("\\x1b[32mOpenSSL_EX\\x1b[0m", "Read (" + len + " bytes)" + safeDump(this.buf, len));
                                    }
                                }
                            } catch(e){}
                        }
                    });
                    break;
                }
            }
        } catch(e){}
    }

    // =========================================================================
    // [Main] 감시 루프
    // =========================================================================
    var hooked = {};

    function monitor() {
        // File
        if (!hooked["file"]) {
            hookFile();
            hooked["file"] = true;
        }

        // SChannel
        if (!hooked["sspi"]) {
            var m = null;
            try { m = Process.findModuleByName("SspiCli.dll"); } catch(e){}
            if (m) {
                hookSChannel(m.name);
                hooked["sspi"] = true;
            }
        }

        // OpenSSL
        try {
            var modules = Process.enumerateModules();
            for(var i=0; i<modules.length; i++) {
                var name = modules[i].name.toLowerCase();
                if((name.indexOf("libssl") !== -1 || name.indexOf("openssl") !== -1) && !hooked[name]) {
                    hookOpenSSL(modules[i].name);
                    hooked[name] = true;
                }
            }
        } catch(e){}
    }

    setInterval(monitor, 1000);
    monitor();
})();
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[!] JS Error: {message['stack']}\x1b[0m")

def main():
    print(f"[*] Monitoring: {TARGET_PREFIX}...")
    device = frida.get_local_device()
    while True:
        try:
            procs = device.enumerate_processes()
            for p in procs:
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    print(f"\n[+] Attaching: {p.name} ({p.pid})")
                    try:
                        session = device.attach(p.pid)
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load()
                        attached_pids.add(p.pid)
                    except Exception as e:
                        print(f"[!] Attach fail: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == "__main__":
    main()

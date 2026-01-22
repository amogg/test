import frida
import time
import sys

# ==============================================================================
# [JavaScript Hooking Code]
# 파일 시스템 + SSL(SChannel/OpenSSL) + 에러 방지 로직 통합
# ==============================================================================
JS_CODE = """
(function() {
    // -------------------------------------------------------------------------
    // 1. 유틸리티: 안전한 문자열 읽기 & 덤프 (호환성 보장)
    // -------------------------------------------------------------------------
    function readSafeString(ptr) {
        if (!ptr || ptr.isNull()) return "(null)";
        try {
            if (typeof ptr.readUtf16String === 'function') return ptr.readUtf16String();
            if (typeof Memory.readUtf16String === 'function') return Memory.readUtf16String(ptr);
        } catch(e) {}
        return "(read error)";
    }

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

    // -------------------------------------------------------------------------
    // 2. 핵심: 에러 없는 주소 찾기 (Safe Resolver)
    // -------------------------------------------------------------------------
    function resolveAddress(moduleName, funcName) {
        var ptr = null;
        try {
            // 1. 표준 방식
            if (Module && typeof Module.findExportByName === 'function') {
                ptr = Module.findExportByName(moduleName, funcName);
            }
        } catch(e) {}

        if (ptr) return ptr;

        try {
            // 2. 모듈 객체를 통한 우회
            if (Process && typeof Process.findModuleByName === 'function') {
                var m = Process.findModuleByName(moduleName);
                if (m && Module && typeof Module.findExportByName === 'function') {
                    ptr = Module.findExportByName(m.name, funcName);
                }
            }
        } catch(e) {}
        return ptr;
    }

    // Fuzzy Search (이름이 포함된 함수 찾기)
    function findAddressFuzzy(moduleName, partialName) {
        try {
            var m = Process.findModuleByName(moduleName);
            if (!m) return null;
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

    function safeHook(moduleName, funcName, callbacks) {
        try {
            var ptr = resolveAddress(moduleName, funcName);
            if (ptr) {
                Interceptor.attach(ptr, callbacks);
                console.log("[+] Hooked: " + moduleName + "!" + funcName);
            }
        } catch(e) {
            // 에러 무시 (스크립트 중단 방지)
        }
    }

    // -------------------------------------------------------------------------
    // 3. 파일 시스템 후킹
    // -------------------------------------------------------------------------
    var fsHooked = false;
    function hookFileSystem() {
        if (fsHooked) return;

        // CreateFileW
        safeHook("kernel32.dll", "CreateFileW", {
            onEnter: function(args) {
                this.path = readSafeString(args[0]);
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf("Windows") === -1 && this.path.indexOf("Font") === -1) {
                    var handle = retval.toInt32 ? retval.toInt32() : retval;
                    var status = (handle === -1) ? "FAILED" : "SUCCESS";
                    console.log("\\x1b[36m[FILE] Create: " + this.path + " -> " + status + "\\x1b[0m");
                }
            }
        });

        // DeleteFileW
        safeHook("kernel32.dll", "DeleteFileW", {
            onEnter: function(args) {
                console.log("\\x1b[31m[FILE] DELETE: " + readSafeString(args[0]) + "\\x1b[0m");
            }
        });

        // MoveFileW
        safeHook("kernel32.dll", "MoveFileW", {
            onEnter: function(args) {
                console.log("\\x1b[33m[FILE] MOVE: " + readSafeString(args[0]) + " -> " + readSafeString(args[1]) + "\\x1b[0m");
            }
        });
        
        fsHooked = true;
    }

    // -------------------------------------------------------------------------
    // 4. SSL 후킹 (SChannel + OpenSSL)
    // -------------------------------------------------------------------------
    function hookSChannel(modName) {
        // 정확한 이름 or Fuzzy 검색
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
                                        console.log("\\x1b[36m[SChannel] Decrypt (" + len + " bytes):\\x1b[0m");
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

                        // 함수 타입별 길이 계산
                        if (this.funcName.indexOf("read") !== -1 && this.funcName.indexOf("_ex") === -1) len = ret;
                        else if (this.funcName.indexOf("write") !== -1) len = this.num;
                        else if (this.funcName.indexOf("_ex") !== -1 && ret === 1 && !this.pReadBytes.isNull()) {
                            len = this.pReadBytes.readPointer().toInt32();
                        }

                        if (len > 0) {
                            var color = this.funcName.indexOf("read") !== -1 ? "\\x1b[35m" : "\\x1b[32m";
                            console.log(color + "[OpenSSL] " + this.funcName + " (" + len + " bytes):\\x1b[0m");
                            console.log(dumpMemory(this.buf, len));
                        }
                    } catch(e) {}
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // 5. Poller (감시 루프)
    // -------------------------------------------------------------------------
    var hookedModules = {};

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

    // 1초 간격 감시 (Lazy Loading 대응)
    console.log("[*] JS Monitor Loaded. Polling started...");
    setInterval(poller, 1000);
    poller();

})();
"""

# ==============================================================================
# [Python Orchestration Code]
# ==============================================================================

# 감시할 프로세스 접두사 (예: aaa_)
TARGET_PREFIX = "aaa_"  
attached_pids = set()

def on_message(message, data):
    """
    JS에서 오는 로그를 출력하는 핸들러
    **중요**: 'log' 타입을 처리해야 console.log가 보입니다.
    """
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'log':
        # JS의 console.log는 이쪽으로 들어옵니다
        print(f"{message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[JS Error] {message['stack']}\x1b[0m")
    else:
        print(f"[?] Unknown message: {message}")

def main():
    print(f"==================================================")
    print(f"[*] Auto Analyzer Started for prefix: '{TARGET_PREFIX}'")
    print(f"[*] Press Ctrl+C to stop.")
    print(f"==================================================")

    device = frida.get_local_device()

    while True:
        try:
            # 1. 프로세스 스캔
            current_procs = device.enumerate_processes()
            
            for p in current_procs:
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    
                    print(f"\n[+] Found Target: {p.name} (PID: {p.pid})")
                    
                    try:
                        # 2. Attach
                        session = device.attach(p.pid)
                        
                        # Detach 핸들러
                        def on_detached(reason, pid=p.pid):
                            print(f"[-] Detached from PID {pid}: {reason}")
                            if pid in attached_pids:
                                attached_pids.remove(pid)

                        session.on('detached', on_detached)
                        
                        # 3. JS 주입
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load()
                        
                        attached_pids.add(p.pid)
                        print(f"[+] Hook injected into {p.name}")
                        
                    except frida.ProcessNotFoundError:
                        print(f"[!] Process {p.pid} ended before attach.")
                    except Exception as e:
                        print(f"[!] Attach Error: {e}")

            time.sleep(1) # CPU 과부하 방지

        except KeyboardInterrupt:
            print("\n[-] Stopping...")
            sys.exit()
        except Exception as e:
            print(f"[!] Main Loop Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()

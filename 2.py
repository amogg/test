import frida
import time
import sys

# ==============================================================================
# [JavaScript Hooking Code (Fixed)]
# 에러 방지 및 호환성 코드가 추가된 버전
# ==============================================================================
JS_CODE = """
(function() {
    // [설정] 이미 후킹된 주소 관리
    var isHooked = {}; 

    // -------------------------------------------------------------------------
    // 1. 호환성 및 유틸리티 (에러 방지 핵심)
    // -------------------------------------------------------------------------
    
    // safeReadString: readUtf16String이 없으면 readUtf16을 시도 (구버전 호환)
    function safeReadString(ptr) {
        if (ptr.isNull()) return "(null)";
        try {
            if (ptr.readUtf16String) return ptr.readUtf16String();
            if (ptr.readUtf16) return ptr.readUtf16(); // 구버전용
            return "Cannot read string";
        } catch(e) {
            return "(read error)";
        }
    }

    function log(type, msg) {
        var colors = {
            "FILE": "\\x1b[36m", "NET": "\\x1b[32m", "SSL": "\\x1b[35m",
            "EXEC": "\\x1b[31m", "REG": "\\x1b[33m", "ERR": "\\x1b[31m", "SYS": "\\x1b[37m"
        };
        var color = colors[type] || colors["SYS"];
        send("[" + type + "] " + msg);
        console.log(color + "[" + type + "] " + msg + "\\x1b[0m");
    }

    function dumpMemory(ptr, length) {
        if (ptr.isNull() || length <= 0) return "";
        try {
            var buf = ptr.readByteArray(length);
            return "\\n" + hexdump(buf, { offset: 0, length: length, header: false, ansi: false });
        } catch (e) { return ""; }
    }

    // -------------------------------------------------------------------------
    // 2. 안전한 후킹 래퍼 (SafeHook)
    // -------------------------------------------------------------------------
    function safeHook(dllName, funcName, callbacks) {
        var fullName = dllName + "!" + funcName;
        if (isHooked[fullName]) return;

        try {
            var ptr = Module.findExportByName(dllName, funcName);
            if (!ptr) return; // 함수 없으면 조용히 패스

            Interceptor.attach(ptr, callbacks);
            isHooked[fullName] = true;
            log("SYS", "Hooked: " + fullName);
        } catch (e) {
            // 에러 나도 멈추지 않음
        }
    }

    // -------------------------------------------------------------------------
    // 3. 메인 후킹 로직
    // -------------------------------------------------------------------------
    function applyHooks() {
        try {
            // [FILE]
            safeHook("kernel32.dll", "CreateFileW", {
                onEnter: function(args) { this.path = safeReadString(args[0]); },
                onLeave: function(retval) {
                    if (this.path && this.path.indexOf("Windows") === -1) {
                        log("FILE", "CreateFile: " + this.path);
                    }
                }
            });
            
            safeHook("kernel32.dll", "DeleteFileW", {
                onEnter: function(args) { log("FILE", "DeleteFile: " + safeReadString(args[0])); }
            });

            // [EXEC]
            safeHook("kernel32.dll", "CreateProcessW", {
                onEnter: function(args) {
                    var app = safeReadString(args[0]);
                    var cmd = safeReadString(args[1]);
                    log("EXEC", "CreateProcess: " + app + " " + cmd);
                }
            });

            // [REG]
            safeHook("advapi32.dll", "RegSetValueExW", {
                onEnter: function(args) { log("REG", "SetValue: " + safeReadString(args[1])); }
            });

            // [NET]
            safeHook("ws2_32.dll", "connect", {
                onEnter: function(args) { log("NET", "Socket Connect"); }
            });
            
            safeHook("ws2_32.dll", "send", {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0) log("NET", "Send (" + len + " bytes)" + dumpMemory(args[1], Math.min(len, 64)));
                }
            });

            // [SSL] Windows Native
            safeHook("secur32.dll", "DecryptMessage", {
                onEnter: function(args) { this.pMessage = args[1]; },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.pMessage) log("SSL", "DecryptMessage (SChannel)");
                }
            });

            // [SSL] OpenSSL (동적 스캔)
            if (Process.enumerateModules && typeof Process.enumerateModules === 'function') {
                findAndHookOpenSSL();
            }

        } catch(e) {
            log("ERR", "applyHooks Error: " + e.message);
        }
    }

    // -------------------------------------------------------------------------
    // 4. OpenSSL 동적 탐지 (안전 버전)
    // -------------------------------------------------------------------------
    function findAndHookOpenSSL() {
        try {
            Process.enumerateModules().forEach(function(m) {
                var name = m.name.toLowerCase();
                if (name.indexOf("ssl") !== -1 || name.indexOf("crypto") !== -1) {
                    // enumerateExports가 없는 경우 대비
                    if (m.enumerateExports) {
                        m.enumerateExports().forEach(function(exp) {
                            if (exp.name === "SSL_read" || exp.name === "SSL_write") {
                                safeHook(m.name, exp.name, {
                                    onEnter: function(args) {
                                        this.ssl = args[0]; this.buf = args[1]; this.num = args[2].toInt32();
                                    },
                                    onLeave: function(retval) {
                                        var ret = retval.toInt32();
                                        if (ret > 0) log("SSL", "OpenSSL Data (" + ret + " bytes)");
                                    }
                                });
                            }
                        });
                    }
                }
            });
        } catch(e) {}
    }

    // -------------------------------------------------------------------------
    // 5. 실행부 (Lazy Loading 제거로 안정성 확보)
    // -------------------------------------------------------------------------
    log("SYS", "Monitor script loaded.");
    
    // 초기 1회 실행
    applyHooks();

    // LoadLibraryW 후킹은 재귀 에러 원인이 되므로, 
    // 필요하다면 1초마다 새로운 모듈을 체크하는 방식으로 변경 (Poller)
    // 여기서는 안정성을 위해 제거했습니다.
})();
"""

# ==============================================================================
# [Python Code]
# ==============================================================================

TARGET_PREFIX = "aaa_"
attached_pids = set()

def on_message(message, data):
    if message['type'] == 'send':
        print(f"{message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[JS Error] {message['stack']}\x1b[0m")

def main():
    print(f"[*] Waiting for processes starting with '{TARGET_PREFIX}'...")
    device = frida.get_local_device()

    while True:
        try:
            processes = device.enumerate_processes()
            for p in processes:
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    print(f"\n[+] Found Target: {p.name} (PID: {p.pid})")
                    try:
                        session = device.attach(p.pid)
                        
                        def on_detached(reason, pid=p.pid):
                            if pid in attached_pids: attached_pids.remove(pid)

                        session.on('detached', on_detached)
                        
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load()
                        
                        attached_pids.add(p.pid)
                        print(f"[+] Hook injected into {p.name}")
                        
                    except Exception as e:
                        print(f"[!] Injection Error: {e}")

            time.sleep(0.5)

        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            # 가끔 프리다 연결 끊길 때 무시하고 재시도
            time.sleep(1)

if __name__ == "__main__":
    main()

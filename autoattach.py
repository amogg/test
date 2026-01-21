import frida
import time
import sys

# ==============================================================================
# [JavaScript Hooking Code]
# 프리다에 주입될 핵심 로직입니다.
# ==============================================================================
JS_CODE = """
(function() {
    // -------------------------------------------------------------------------
    // 1. 유틸리티 및 설정
    // -------------------------------------------------------------------------
    var isHooked = {}; // 중복 후킹 방지용 맵

    function log(type, msg) {
        // 색상 코드로 가독성 확보
        var colors = {
            "FILE": "\\x1b[36m", // Cyan
            "NET": "\\x1b[32m",  // Green
            "SSL": "\\x1b[35m",  // Magenta
            "EXEC": "\\x1b[31m", // Red
            "REG": "\\x1b[33m",  // Yellow
            "ERR": "\\x1b[31m",  // Red (Error)
            "SYS": "\\x1b[37m"   // White
        };
        var color = colors[type] || colors["SYS"];
        var reset = "\\x1b[0m";
        send("[" + type + "] " + msg); // Python으로 전송 (콘솔 출력용)
        console.log(color + "[" + type + "] " + msg + reset);
    }

    // 메모리 덤프 헬퍼 (SSL 데이터 확인용)
    function dumpMemory(ptr, length) {
        if (ptr.isNull() || length <= 0) return "";
        try {
            var buf = ptr.readByteArray(length);
            // 사람이 읽을 수 있는 문자열로 변환 시도 (안되면 HEX)
            return "\\n" + hexdump(buf, { offset: 0, length: length, header: false, ansi: false });
        } catch (e) {
            return "(dump error)";
        }
    }

    // -------------------------------------------------------------------------
    // 2. 안전한 후킹 함수 (Exception Handling & Lazy Loading Support)
    // -------------------------------------------------------------------------
    function safeHook(dllName, funcName, callbacks) {
        var fullName = dllName + "!" + funcName;
        if (isHooked[fullName]) return; // 이미 후킹됨

        try {
            var ptr = Module.findExportByName(dllName, funcName);
            // DLL은 로드되었으나 함수가 없는 경우도 있음
            if (!ptr) {
                // DLL 자체가 메모리에 없는지 확인
                var module = Process.findModuleByName(dllName);
                if (!module) {
                    // [Lazy Loading 대응] DLL이 아직 로드 안 됨 -> 대기 리스트 같은게 필요하지만
                    // 여기서는 LoadLibrary 후킹에서 처리하도록 패스합니다.
                    return; 
                }
                return; // DLL은 있는데 함수가 없으면 패스
            }

            Interceptor.attach(ptr, callbacks);
            isHooked[fullName] = true;
            log("SYS", "Hooked: " + fullName);

        } catch (e) {
            // 치명적이지 않은 에러는 로그만 남기고 무시
            // log("ERR", "Failed to hook " + fullName + ": " + e.message);
        }
    }

    // -------------------------------------------------------------------------
    // 3. 타겟 함수 정의 (시스템 중요 함수)
    // -------------------------------------------------------------------------
    function applyHooks() {
        
        // [FILE] 파일 조작
        safeHook("kernel32.dll", "CreateFileW", {
            onEnter: function(args) {
                this.path = args[0].readUtf16String();
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf("Windows") === -1) { 
                    log("FILE", "CreateFile: " + this.path);
                }
            }
        });
        
        safeHook("kernel32.dll", "DeleteFileW", {
            onEnter: function(args) { log("FILE", "DeleteFile: " + args[0].readUtf16String()); }
        });

        // [EXEC] 프로세스 실행 (가장 중요)
        safeHook("kernel32.dll", "CreateProcessW", {
            onEnter: function(args) {
                var app = args[0].isNull() ? "" : args[0].readUtf16String();
                var cmd = args[1].isNull() ? "" : args[1].readUtf16String();
                log("EXEC", "CreateProcess: " + app + " " + cmd);
            }
        });

        // [REG] 레지스트리 (지속성)
        safeHook("advapi32.dll", "RegSetValueExW", {
            onEnter: function(args) {
                var key = args[1].isNull() ? "(default)" : args[1].readUtf16String();
                log("REG", "SetValue: " + key);
            }
        });

        // [NET] 일반 소켓 통신 (WinSock)
        safeHook("ws2_32.dll", "connect", {
            onEnter: function(args) { log("NET", "Socket Connect"); }
        });
        
        safeHook("ws2_32.dll", "send", {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 0) log("NET", "Send (" + len + " bytes)" + dumpMemory(args[1], Math.min(len, 64)));
            }
        });

        // [SSL] Windows Native SSL (SChannel - DecryptMessage)
        // 암호화된 패킷이 복호화된 직후(onLeave)를 잡습니다.
        safeHook("secur32.dll", "DecryptMessage", {
            onEnter: function(args) {
                this.pMessage = args[1]; // SecBufferDesc 포인터 저장
            },
            onLeave: function(retval) {
                // 성공(SEC_E_OK = 0) 시 데이터 확인
                if (retval.toInt32() === 0 && this.pMessage) {
                    // 구조체 파싱이 복잡하므로 간단히 알림만 (필요시 구조체 파싱 로직 추가 가능)
                    log("SSL", "DecryptMessage called (SChannel Traffic)");
                }
            }
        });

        // [SSL] OpenSSL (동적 스캔)
        // 정적 Import가 아니라 LoadLibrary로 불러오는 경우 대비
        findAndHookOpenSSL();
    }

    // -------------------------------------------------------------------------
    // 4. OpenSSL 동적 후킹 (함수 이름 기반 검색)
    // -------------------------------------------------------------------------
    function findAndHookOpenSSL() {
        Process.enumerateModules().forEach(function(m) {
            // 모듈 이름에 ssl이나 crypto가 들어가는지 확인
            if (m.name.toLowerCase().indexOf("ssl") !== -1 || m.name.toLowerCase().indexOf("crypto") !== -1) {
                var exports = m.enumerateExports();
                exports.forEach(function(exp) {
                    if (exp.name === "SSL_read" || exp.name === "SSL_write") {
                        safeHook(m.name, exp.name, {
                            onEnter: function(args) {
                                this.ssl = args[0];
                                this.buf = args[1];
                                this.num = args[2].toInt32();
                            },
                            onLeave: function(retval) {
                                var ret = retval.toInt32();
                                if (ret > 0) {
                                    // SSL_read: onLeave에서 데이터 확인
                                    // SSL_write: onEnter에서 데이터 확인 (여기선 편의상 묶음)
                                    log("SSL", "OpenSSL Data (" + ret + " bytes)");
                                    // log("SSL", dumpMemory(this.buf, Math.min(ret, 64))); // 데이터 덤프 필요시 주석 해제
                                }
                            }
                        });
                    }
                });
            }
        });
    }

    // -------------------------------------------------------------------------
    // 5. Lazy Loading 대응 (LoadLibraryW 후킹)
    // -------------------------------------------------------------------------
    // 프로그램이 실행 중에 DLL을 로드하면, 그때 다시 applyHooks를 실행해
    // 아직 못 잡은 함수들을 후킹합니다.
    var pLoadLibraryW = Module.findExportByName("kernel32.dll", "LoadLibraryW");
    if (pLoadLibraryW) {
        Interceptor.attach(pLoadLibraryW, {
            onLeave: function(retval) {
                // DLL 로드 완료 직후, 다시 후킹 시도
                // (성능을 위해 딜레이를 주거나, 특정 DLL일 때만 할 수도 있음)
                applyHooks(); 
            }
        });
    }

    // [초기 실행]
    log("SYS", "Monitor script loaded.");
    applyHooks();

})();
"""

# ==============================================================================
# [Python Orchestration Code]
# 프로세스 감시 및 주입 로직
# ==============================================================================

TARGET_PREFIX = "aaa_"  # 감시할 프로세스 이름 접두사
attached_pids = set()

def on_message(message, data):
    """JS에서 온 로그를 이쁘게 출력"""
    if message['type'] == 'send':
        print(f"{message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[JS Error] {message['stack']}\x1b[0m")

def main():
    print(f"[*] Waiting for processes starting with '{TARGET_PREFIX}'...")
    print("[*] Press Ctrl+C to stop.")

    device = frida.get_local_device()

    while True:
        try:
            # 1. 현재 프로세스 목록 스캔
            current_procs = device.enumerate_processes()
            
            for p in current_procs:
                # 2. 타겟 확인 및 중복 방지
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    
                    print(f"\n[+] Found Target: {p.name} (PID: {p.pid})")
                    
                    try:
                        # 3. Attach 및 스크립트 로드
                        session = device.attach(p.pid)
                        
                        # 프로세스 종료 감지 핸들러
                        def on_detached(reason, pid=p.pid):
                            print(f"[-] Detached from PID {pid}: {reason}")
                            if pid in attached_pids:
                                attached_pids.remove(pid)

                        session.on('detached', on_detached)
                        
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load()
                        
                        attached_pids.add(p.pid)
                        print(f"[+] Hook injected into {p.name}")
                        
                        # (선택) 프로세스를 초기에 멈춰두고 싶다면 device.resume(p.pid) 사용 필요할 수 있음
                        # 여기서는 Running 상태에 바로 꽂는 방식
                        
                    except frida.ProcessNotFoundError:
                        print(f"[!] Process {p.pid} died too fast.")
                    except Exception as e:
                        print(f"[!] Injection Failed for {p.pid}: {e}")

            time.sleep(0.5) # CPU 과부하 방지

        except KeyboardInterrupt:
            print("\n[*] Exiting...")
            sys.exit()
        except Exception as e:
            # 프리다 연결 에러 등
            print(f"[!] Monitor Loop Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()

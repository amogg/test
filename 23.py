import frida
import sys
import time

# 감시할 프로세스 이름 (접두사)
TARGET_PREFIX = "aaa_"
attached_pids = set()

# ==============================================================================
# [JavaScript Code] - 정확성 및 안정성 최우선 버전
# ==============================================================================
JS_CODE = """
(function() {
    // -------------------------------------------------------------------------
    // [설정] 유틸리티 (Memory 객체 직접 사용으로 에러 원천 차단)
    // -------------------------------------------------------------------------
    function sendLog(header, msg) {
        send(header + " " + msg);
    }

    function safeReadString(ptr) {
        if (ptr.isNull()) return "(null)";
        try {
            return Memory.readUtf16String(ptr);
        } catch(e) {
            return "(string read error)";
        }
    }

    function safeDump(ptr, len) {
        if (ptr.isNull() || len <= 0) return "";
        try {
            var buf = Memory.readByteArray(ptr, Math.min(len, 128)); // 128바이트만
            // hexdump가 없어도 동작하도록 처리
            if (typeof hexdump === 'function') {
                return "\\n" + hexdump(buf, { offset: 0, length: Math.min(len, 128), header: false, ansi: false });
            }
            return " [Hexdump unavailable]";
        } catch(e) { return ""; }
    }

    // -------------------------------------------------------------------------
    // [핵심] 모듈 내 함수 검색기 (Fuzzy Search)
    // 정확한 이름을 몰라도 'SSL_read'가 포함된 함수를 찾아냄
    // -------------------------------------------------------------------------
    function findExportMatch(modName, keyword) {
        var m = Process.findModuleByName(modName);
        if (!m) return null;

        try {
            var exports = Module.enumerateExports(modName);
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name.indexOf(keyword) !== -1) {
                    return exports[i]; // { name: ..., address: ... } 반환
                }
            }
        } catch(e) {}
        return null;
    }

    // -------------------------------------------------------------------------
    // 1. 파일 시스템 후킹 (Kernel32)
    // -------------------------------------------------------------------------
    function hookFile() {
        var pCreate = Module.findExportByName("kernel32.dll", "CreateFileW");
        if (pCreate) {
            Interceptor.attach(pCreate, {
                onEnter: function(args) {
                    this.path = safeReadString(args[0]);
                },
                onLeave: function(retval) {
                    // 시스템 파일 제외하고 로그 출력
                    if (this.path.indexOf("Windows") === -1 && this.path.indexOf(".dll") === -1) {
                        sendLog("[FILE]", "Create: " + this.path);
                    }
                }
            });
        }
        
        var pWrite = Module.findExportByName("kernel32.dll", "WriteFile");
        if (pWrite) {
             Interceptor.attach(pWrite, {
                onEnter: function(args) {
                    // args[1]: Buffer, args[2]: Size
                    this.len = args[2].toInt32();
                    if (this.len > 0) {
                        // 파일 쓰기 내용 확인 (너무 많으면 주석 처리)
                        // sendLog("[FILE]", "Write (" + this.len + " bytes)");
                    }
                }
             });
        }
    }

    // -------------------------------------------------------------------------
    // 2. Windows Native SSL (SChannel)
    // -------------------------------------------------------------------------
    function hookSChannel(modName) {
        // 정확한 함수 주소를 찾기 위해 검색
        var exp = findExportMatch(modName, "DecryptMessage"); 
        if (!exp) return;

        sendLog("[SYS]", "Hooking SChannel: " + exp.name + " in " + modName);

        Interceptor.attach(exp.address, {
            onEnter: function(args) { 
                this.msg = args[1]; // SecBufferDesc
            },
            onLeave: function(retval) {
                // 성공(0)이고 메시지 포인터가 있을 때만
                if (retval.toInt32() === 0 && this.msg) {
                    try {
                        // x64 구조체 오프셋 하드코딩 (가장 확실함)
                        var count = this.msg.add(4).readU32();        // cBuffers
                        var pBufs = this.msg.add(8).readPointer();    // pBuffers
                        
                        for (var i = 0; i < count; i++) {
                            var cur = pBufs.add(i * 16); // sizeof(SecBuffer) = 16
                            var type = cur.add(4).readU32();
                            
                            // Type 1 = SECBUFFER_DATA (복호화된 평문)
                            if (type === 1) {
                                var len = cur.readU32();
                                var buf = cur.add(8).readPointer();
                                if (len > 0) {
                                    sendLog("\\x1b[36m[SChannel]\\x1b[0m", "Decrypt (" + len + " bytes)" + safeDump(buf, len));
                                }
                            }
                        }
                    } catch(e) {}
                }
            }
        });
    }

    // -------------------------------------------------------------------------
    // 3. OpenSSL (모든 버전 대응)
    // -------------------------------------------------------------------------
    function hookOpenSSL(modName) {
        sendLog("[SYS]", "Inspecting OpenSSL Module: " + modName);

        // A. SSL_read (기본)
        var expRead = findExportMatch(modName, "SSL_read");
        if (expRead && expRead.name.indexOf("_ex") === -1) { // _ex가 아닌 순수 SSL_read
            sendLog("[SYS]", "Hooking " + expRead.name);
            Interceptor.attach(expRead.address, {
                onEnter: function(args) { this.buf = args[1]; },
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0) {
                        sendLog("\\x1b[32m[OpenSSL]\\x1b[0m", "Read (" + len + " bytes)" + safeDump(this.buf, len));
                    }
                }
            });
        }

        // B. SSL_write (기본)
        var expWrite = findExportMatch(modName, "SSL_write");
        if (expWrite && expWrite.name.indexOf("_ex") === -1) {
            sendLog("[SYS]", "Hooking " + expWrite.name);
            Interceptor.attach(expWrite.address, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0) {
                        sendLog("\\x1b[33m[OpenSSL]\\x1b[0m", "Write (" + len + " bytes)" + safeDump(args[1], len));
                    }
                }
            });
        }

        // C. SSL_read_ex (확장형 - 최신 앱들이 많이 사용)
        // int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
        var expReadEx = findExportMatch(modName, "SSL_read_ex");
        if (expReadEx) {
            sendLog("[SYS]", "Hooking " + expReadEx.name);
            Interceptor.attach(expReadEx.address, {
                onEnter: function(args) {
                    this.buf = args[1];
                    this.pReadBytes = args[3]; // 실제 읽은 길이가 저장될 포인터
                },
                onLeave: function(retval) {
                    // 리턴값 1이 성공
                    if (retval.toInt32() === 1 && !this.pReadBytes.isNull()) {
                        var len = this.pReadBytes.readU64().toNumber(); // x64 size_t
                        if (len > 0) {
                             sendLog("\\x1b[32m[OpenSSL]\\x1b[0m", "Read_EX (" + len + " bytes)" + safeDump(this.buf, len));
                        }
                    }
                }
            });
        }
        
        // D. SSL_write_ex (확장형)
        var expWriteEx = findExportMatch(modName, "SSL_write_ex");
        if (expWriteEx) {
            sendLog("[SYS]", "Hooking " + expWriteEx.name);
            Interceptor.attach(expWriteEx.address, {
                onEnter: function(args) {
                     // args[2]가 길이
                     var len = args[2].toInt32(); 
                     if (len > 0) {
                         sendLog("\\x1b[33m[OpenSSL]\\x1b[0m", "Write_EX (" + len + " bytes)" + safeDump(args[1], len));
                     }
                }
            });
        }
    }

    // -------------------------------------------------------------------------
    // [메인 루프] 감시 시작 (Polling)
    // -------------------------------------------------------------------------
    var hooked = {};

    function monitor() {
        // 1. 파일은 즉시 시도
        if (!hooked["file"]) {
            hookFile();
            hooked["file"] = true;
        }

        // 2. SChannel (SspiCli.dll)
        if (!hooked["sspi"]) {
            var m = Process.findModuleByName("SspiCli.dll");
            if (m) {
                hookSChannel(m.name);
                hooked["sspi"] = true;
            }
        }

        // 3. OpenSSL (이름에 ssl, crypto 등이 들어간 모듈 검색)
        // 이미 후킹한 모듈은 건너뜀
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var name = modules[i].name.toLowerCase();
            if ((name.indexOf("libssl") !== -1 || name.indexOf("openssl") !== -1) && !hooked[name]) {
                hookOpenSSL(modules[i].name);
                hooked[name] = true;
            }
        }
    }

    // 1초마다 새로운 DLL이 로드되었는지 확인
    setInterval(monitor, 1000);
    monitor(); // 시작

})();
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[!] JS Error: {message['stack']}\x1b[0m")

def main():
    print(f"[*] Monitoring processes starting with: {TARGET_PREFIX} ...")
    device = frida.get_local_device()
    
    while True:
        try:
            processes = device.enumerate_processes()
            for p in processes:
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    print(f"\n[+] Attaching to {p.name} (PID: {p.pid})")
                    
                    try:
                        session = device.attach(p.pid)
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load()
                        attached_pids.add(p.pid)
                    except Exception as e:
                        print(f"[!] Failed to attach: {e}")
                        
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == "__main__":
    main()

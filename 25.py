import frida
import sys
import time

# 감시할 프로세스 접두사
TARGET_PREFIX = "aaa_"
attached_pids = set()

# ==============================================================================
# [진단용 JS] 무조건 로그를 출력하도록 설계됨
# ==============================================================================
JS_CODE = """
(function() {
    // 1. JS 로드 즉시 생존 신고
    send("========================================");
    send("[*] JS LOADED! (I am alive inside the process)");
    send("[*] Process Arch: " + Process.arch);
    send("[*] Pointer Size: " + Process.pointerSize);
    send("========================================");

    // 2. 모듈 검색 테스트
    var kernel32 = Process.findModuleByName("kernel32.dll");
    if (kernel32) {
        send("[+] Kernel32 found at: " + kernel32.base);
    } else {
        send("[-] Kernel32 NOT found (Something is very wrong)");
    }

    // 3. 함수 주소 찾기 테스트 (CreateFileW)
    var pCreate = Module.findExportByName("kernel32.dll", "CreateFileW");
    if (pCreate) {
        send("[+] CreateFileW address: " + pCreate);
        
        // 후킹 시도
        try {
            Interceptor.attach(pCreate, {
                onEnter: function(args) {
                    send("[HIT] CreateFileW called!");
                }
            });
            send("[+] Hook installed on CreateFileW");
        } catch(e) {
            send("[!] Hook failed: " + e.message);
        }

    } else {
        send("[-] CreateFileW NOT found via Export");
    }

    // 4. SSL 모듈 유무 확인
    var modules = Process.enumerateModules();
    var sslFound = false;
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name.toLowerCase();
        if (name.indexOf("ssl") !== -1 || name.indexOf("crypto") !== -1 || name.indexOf("secur") !== -1) {
            send("[*] Crypto Module Found: " + modules[i].name + " @ " + modules[i].base);
            sslFound = true;
        }
    }
    if (!sslFound) {
        send("[-] No SSL/Crypto modules found currently loaded.");
    }

    // 5. 하트비트 (1초마다 생존신고)
    setInterval(function() {
        send("[*] Heartbeat: Script is still running...");
    }, 2000);

})();
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"{message['payload']}")
    elif message['type'] == 'error':
        print(f"\x1b[31m[JS Error] {message['stack']}\x1b[0m")

def main():
    print(f"[*] Waiting for {TARGET_PREFIX}...")
    device = frida.get_local_device()

    while True:
        try:
            procs = device.enumerate_processes()
            for p in procs:
                if p.name.startswith(TARGET_PREFIX) and p.pid not in attached_pids:
                    print(f"\n[+] Found {p.name} ({p.pid}). Attaching...")
                    try:
                        session = device.attach(p.pid)
                        script = session.create_script(JS_CODE)
                        script.on('message', on_message)
                        script.load() # 여기서 JS가 실행됩니다.
                        
                        attached_pids.add(p.pid)
                        print("[+] Script Loaded. Waiting for logs...")
                        
                    except Exception as e:
                        print(f"[!] Attach Error: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == "__main__":
    main()

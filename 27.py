import frida
import sys
import time

TARGET_PREFIX = "aaa_"
attached_pids = set()

JS_CODE = """
(function() {
    function log(msg) { send(msg); }

    // [Step 1] 기본 환경 진단
    log("========================================");
    log("[*] Step 1: Environment Check");
    try {
        log("    -> Arch: " + Process.arch);
        log("    -> PointerSize: " + Process.pointerSize);
    } catch(e) { log("    [!] Process info error: " + e.message); }

    // [Step 2] Kernel32 및 CreateFileW 주소 확인
    log("[*] Step 2: Kernel32 Check");
    var pCreate = null;
    try {
        pCreate = Module.findExportByName("kernel32.dll", "CreateFileW");
        log("    -> CreateFileW Address: " + pCreate);
    } catch(e) { log("    [!] FindExport Error: " + e.message); }

    // [Step 3] 후킹 테스트 (CreateFileW)
    log("[*] Step 3: Hook Test");
    if (pCreate) {
        try {
            Interceptor.attach(pCreate, {
                onEnter: function(args) {
                    // 여기서 복잡한 문자열 읽기 하지 않음 (죽을까봐)
                    send("[HIT] CreateFileW called!"); 
                }
            });
            log("    -> Hook Success! (Try opening a file now)");
        } catch(e) { log("    [!] Hook Error: " + e.message); }
    } else {
        log("    [!] Skip Hook Test (Address not found)");
    }

    // [Step 4] 모듈 목록 안전 스캔 (여기가 에러 났던 곳)
    log("[*] Step 4: Safe Module Scan");
    try {
        var modules = Process.enumerateModules();
        log("    -> Total Modules: " + modules.length);
        
        var foundSSL = false;
        for (var i = 0; i < modules.length; i++) {
            try {
                // name 속성이 없는 경우가 있을 수 있으므로 안전하게 접근
                var m = modules[i];
                var name = "unknown";
                if (m.name) name = m.name;
                
                // toLowerCase()가 함수인지 확인 후 호출
                var lowName = name;
                if (name.toLowerCase && typeof name.toLowerCase === 'function') {
                    lowName = name.toLowerCase();
                }

                // SSL 관련 모듈인지 확인
                if (lowName.indexOf("ssl") !== -1 || lowName.indexOf("secur") !== -1 || lowName.indexOf("crypt") !== -1) {
                    log("    [Found Crypto] " + name + " @ " + m.base);
                    foundSSL = true;
                }
            } catch(innerE) {
                // 개별 모듈 확인 중 에러나도 무시하고 다음으로
            }
        }
        
        if (!foundSSL) log("    [-] No obvious SSL modules found.");

    } catch(e) {
        log("    [!] Module Scan Critical Error: " + e.message);
    }

    log("========================================");
    log("[*] DIAGNOSTICS COMPLETE. Waiting for [HIT] logs...");

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
                        script.load()
                        attached_pids.add(p.pid)
                    except Exception as e:
                        print(f"[!] Attach Error: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == "__main__":
    main()

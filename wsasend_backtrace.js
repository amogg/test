/*
 * WSASend Backtracer for Finding Encryption Functions
 * Compatible with Frida 17.x
 */

const COLORS = {
    TRACE: "\x1b[33m", // Yellow (Call Stack)
    DATA:  "\x1b[36m", // Cyan (Data Hexdump)
    RESET: "\x1b[0m"
};

function hookWSASendWithBacktrace() {
    // 1. WSASend 주소 찾기 (전역 검색)
    const wsaSendAddr = Module.getGlobalExportByName("WSASend");

    if (!wsaSendAddr) {
        console.error("[-] WSASend not found. Is ws2_32.dll loaded?");
        return;
    }

    console.log(`[+] Hooking WSASend at ${wsaSendAddr}`);
    console.log("[*] Waiting for traffic... (Check the Call Stack!)");

    Interceptor.attach(wsaSendAddr, {
        onEnter(args) {
            // int WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, ...)
            
            const socket = args[0].toInt32();
            const lpBuffers = ptr(args[1]);
            const dwBufferCount = args[2].toInt32();

            // 필터링: 데이터가 없으면 무시 (노이즈 제거)
            if (dwBufferCount === 0) return;

            // ---------------------------------------------------------
            // 1. [핵심] Backtrace 출력 (누가 WSASend를 불렀는가?)
            // ---------------------------------------------------------
            console.log(`\n${COLORS.TRACE}[!] WSASend called! Tracing callers...${COLORS.RESET}`);
            
            // 현재 스레드의 스택(Call Stack)을 가져와서 심볼로 변환
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .join("\n\t  <- ");

            console.log(`\t  <- ${backtrace}`);

            // ---------------------------------------------------------
            // 2. 데이터 덤프 (WSABUF 구조체 파싱)
            // ---------------------------------------------------------
            console.log(`${COLORS.DATA}[Data Dump]${COLORS.RESET}`);
            
            for (let i = 0; i < dwBufferCount; i++) {
                try {
                    // x64 기준 WSABUF: { ULONG len (4), char* buf (8) } = 16 bytes
                    // x86 기준 WSABUF: { ULONG len (4), char* buf (4) } = 8 bytes
                    const structSize = Process.pointerSize === 8 ? 16 : 8;
                    const offsetBuf = Process.pointerSize === 8 ? 8 : 4;

                    const curBufStruct = lpBuffers.add(i * structSize);
                    const len = curBufStruct.readU32();
                    const bufPtr = curBufStruct.add(offsetBuf).readPointer();

                    if (len > 0) {
                        // 너무 길면 256바이트만 출력 (렉 방지)
                        // const dumpLen = len > 256 ? 256 : len;
                        
                        console.log(` Buffer #${i} (Size: ${len})`);
                        console.log(hexdump(bufPtr, {
                            offset: 0,
                            length: len, // 전체 다 보려면 dumpLen 대신 len 사용
                            header: false,
                            ansi: true
                        }));
                    }
                } catch (e) {
                    console.log(`[!] Error parsing buffer #${i}: ${e.message}`);
                }
            }
            console.log("---------------------------------------------------------------");
        }
    });
}

// 스크립트 실행
setTimeout(hookWSASendWithBacktrace, 1000);

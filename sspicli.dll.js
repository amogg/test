/*
 * Windows Sspicli.dll / Secur32.dll SSL Logger
 * Hooks EncryptMessage (Send) & DecryptMessage (Recv)
 * Compatible with Frida 17.x
 */

// 구조체 오프셋 및 상수 정의
const SECBUFFER_DATA = 1; // 우리가 찾는 실제 데이터 타입
const SECBUFFER_VERSION = 0;

// 색상 정의
const C_SEND = "\x1b[36m"; // Cyan
const C_RECV = "\x1b[32m"; // Green
const C_RESET = "\x1b[0m";

function hookSspi() {
    // 1. Sspicli.dll 또는 Secur32.dll에서 함수 주소 찾기
    // 보통 Sspicli.dll에 구현되어 있으나, 전역으로 찾는 것이 가장 확실합니다.
    let encryptAddr = Module.findExportByName("Sspicli.dll", "EncryptMessage");
    let decryptAddr = Module.findExportByName("Sspicli.dll", "DecryptMessage");

    // 만약 Sspicli에 없으면 Secur32에서 찾음 (구버전 호환)
    if (!encryptAddr) encryptAddr = Module.findExportByName("Secur32.dll", "EncryptMessage");
    if (!decryptAddr) decryptAddr = Module.findExportByName("Secur32.dll", "DecryptMessage");

    if (!encryptAddr || !decryptAddr) {
        console.error("[-] Failed to find EncryptMessage or DecryptMessage.");
        return;
    }

    console.log("[+] EncryptMessage found at: " + encryptAddr);
    console.log("[+] DecryptMessage found at: " + decryptAddr);

    // 2. SecBufferDesc 구조체 파싱 헬퍼 함수
    // Windows SSPI는 여러 개의 버퍼(헤더, 데이터, 트레일러 등)를 배열로 전달합니다.
    function dumpSecBufferDesc(pDesc, label, color) {
        if (pDesc.isNull()) return;

        try {
            // SecBufferDesc 구조:
            // ULONG ulVersion;
            // ULONG cBuffers; (버퍼 개수)
            // PSecBuffer pBuffers; (버퍼 배열 포인터)
            
            // pDesc는 포인터이므로 읽어옵니다.
            const cBuffers = pDesc.add(4).readU32(); // 두 번째 4바이트가 개수
            const pBuffers = ptr(pDesc.add(8).readPointer()); // 세 번째가 배열 포인터 (64bit 기준 offset 8)

            // 32bit 환경이라면 offset이 다를 수 있음 (ulVersion(4) + cBuffers(4) -> pBuffers는 offset 8)
            // Process.pointerSize로 체크 가능하나 통상 64bit 환경 가정

            for (let i = 0; i < cBuffers; i++) {
                // SecBuffer 구조 (배열의 각 요소):
                // ULONG cbBuffer; (크기)
                // ULONG BufferType; (타입)
                // PVOID pvBuffer; (데이터 포인터)
                
                // SecBuffer 하나의 크기는 sizeof(ULONG)*2 + sizeof(PVOID) 
                // 64bit: 4 + 4 + 8 = 16 bytes
                // 32bit: 4 + 4 + 4 = 12 bytes
                const structSize = (Process.pointerSize === 8) ? 16 : 12;
                const currentBuffer = pBuffers.add(i * structSize);

                const cbBuffer = currentBuffer.readU32();
                const bufferType = currentBuffer.add(4).readU32();
                const pvBuffer = ptr(currentBuffer.add(8).readPointer()); // 64bit 기준 offset 8

                // BufferType이 1 (SECBUFFER_DATA)인 경우만 출력 (헤더/패딩 제외)
                if (bufferType === SECBUFFER_DATA && cbBuffer > 0) {
                    console.log(`${color}[${label}] Data (Size: ${cbBuffer})${C_RESET}`);
                    console.log(hexdump(pvBuffer, {
                        offset: 0,
                        length: cbBuffer,
                        header: false,
                        ansi: true
                    }));
                    console.log("\n");
                }
            }
        } catch (e) {
            console.log("[!] Error parsing SecBuffer: " + e.message);
        }
    }

    // 3. EncryptMessage 후킹 (보낼 데이터 잡기)
    // SECURITY_STATUS EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo)
    // pMessage 안에 '평문'이 들어있고, 함수가 실행되면 그 자리에서 암호화됨.
    // 따라서 *onEnter*에서 데이터를 뽑아야 함.
    Interceptor.attach(encryptAddr, {
        onEnter(args) {
            const pMessage = ptr(args[2]); // 3번째 인자가 pMessage (SecBufferDesc)
            dumpSecBufferDesc(pMessage, "+ EncryptMessage (Send)", C_SEND);
        }
    });

    // 4. DecryptMessage 후킹 (받은 데이터 잡기)
    // SECURITY_STATUS DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP)
    // 함수 실행 전에는 암호문, 실행 후(*onLeave*)에 평문으로 바뀜.
    Interceptor.attach(decryptAddr, {
        onEnter(args) {
            this.pMessage = ptr(args[1]); // 2번째 인자가 pMessage
        },
        onLeave(retval) {
            // 성공(SEC_E_OK = 0)했을 때만 덤프
            if (retval.toInt32() === 0) {
                dumpSecBufferDesc(this.pMessage, "+ DecryptMessage (Recv)", C_RECV);
            }
        }
    });
}

// 실행
setTimeout(hookSspi, 1000);

/*
 * Windows CryptoAPI Memory Hunter
 * Targets: CryptDecryptMessage (Source) & CryptMemFree (Cleanup)
 */

const COLORS = {
    DEC: "\x1b[32m", // Green (Decrypt Success)
    FREE: "\x1b[31m", // Red (Memory Free)
    RESET: "\x1b[0m"
};

function hookCryptoMemory() {
    const crypt32 = "crypt32.dll";
    
    // 1. 데이터를 만들어내는 놈 (CryptDecryptMessage)
    const decryptMsg = Module.findExportByName(crypt32, "CryptDecryptMessage");
    
    // 2. 데이터를 지우는 놈 (CryptMemFree)
    const memFree = Module.findExportByName(crypt32, "CryptMemFree");

    console.log("[*] Hooking CryptDecryptMessage & CryptMemFree...");

    // =============================================================
    // 1. CryptDecryptMessage 후킹 (가장 중요)
    // =============================================================
    if (decryptMsg) {
        Interceptor.attach(decryptMsg, {
            onEnter(args) {
                // 나중에 결과값을 읽기 위해 포인터 주소를 저장
                this.ppbDecrypted = ptr(args[4]); // 평문 버퍼 포인터의 포인터
                this.pcbDecrypted = ptr(args[5]); // 평문 길이 포인터
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0) { // 성공 시
                    const len = this.pcbDecrypted.readU32();
                    const pPlain = this.ppbDecrypted.readPointer(); // 실제 평문 위치

                    if (len > 0) {
                        console.log(`${COLORS.DEC}[+] CryptDecryptMessage Success! (Size: ${len})${COLORS.RESET}`);
                        console.log(hexdump(pPlain, { length: len, header: false, ansi: true }));
                        console.log("---------------------------------------------------");
                    }
                }
            }
        });
    }

    // =============================================================
    // 2. CryptMemFree 후킹 (버려지는 데이터 훔쳐보기)
    // =============================================================
    // 주의: CryptMemFree는 '길이(Size)' 인자가 없습니다. 그냥 주소만 줍니다.
    // 그래서 적당히 256바이트 정도만 찍어봅니다.
    if (memFree) {
        Interceptor.attach(memFree, {
            onEnter(args) {
                const pvData = ptr(args[0]); // 해제하려는 메모리 주소
                
                if (!pvData.isNull()) {
                    // 필터링: 너무 자주 호출되면 주석 처리하세요.
                    // console.log(`${COLORS.FREE}[-] CryptMemFree called (Address: ${pvData})${COLORS.RESET}`);
                    
                    try {
                        // 메모리가 해제되기 직전, 내용물을 살짝 봅니다.
                        // 텍스트일 수도 있고, 바이너리일 수도 있습니다.
                        // 길이를 모르니 128바이트만 읽어봅니다.
                        const preview = hexdump(pvData, { length: 128, header: false, ansi: true });
                        
                        // 너무 노이즈가 많으면, 특정 패턴(HTTP, JSON 등)이 보일 때만 출력하도록 if문 추가 가능
                        // console.log(preview); 
                    } catch (e) {}
                }
            }
        });
    }
}

setTimeout(hookCryptoMemory, 1000);

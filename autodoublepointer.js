/*
 * Auto Deep Argument Inspector
 * 모든 인자에 대해 포인터 체인(Pointer Chain)을 자동으로 추적합니다.
 */

// =================================================================
// [설정] 함수 주소
// =================================================================
const TARGET_IDA_ADDR = "0x140149610"; 
const IMAGE_BASE      = "0x140000000"; 
const ARG_COUNT       = 4; // 검사할 인자 개수 (Fastcall 기본 4개 + 필요시 늘리세요)

// =================================================================

const C_LEVEL0 = "\x1b[36m"; // Cyan (Arg)
const C_LEVEL1 = "\x1b[33m"; // Yellow (Pointer)
const C_LEVEL2 = "\x1b[32m"; // Green (Double Pointer value)
const C_ERR    = "\x1b[31m"; // Red
const C_RST    = "\x1b[0m";

function autoInspect() {
    // 모듈 찾기 및 주소 계산 (이전과 동일)
    const module = Process.mainModule;
    if (!module) return;
    const offset = ptr(TARGET_IDA_ADDR).sub(ptr(IMAGE_BASE));
    const targetAddr = module.base.add(offset);

    console.log(`[*] Hooking Auto-Deep Inspector at ${targetAddr}`);

    // =============================================================
    // [핵심] 재귀적으로 메모리를 파고드는 함수
    // ptrVal: 현재 주소값, depth: 현재 깊이 (0=인자, 1=포인터, 2=이중포인터)
    // =============================================================
    function probePointer(ptrVal, depth) {
        // 1. NULL 체크
        if (ptrVal.isNull()) return "NULL";

        // 2. 이 값이 유효한 메모리 주소인지 확인 (가장 중요)
        // 값이 너무 작으면(예: 0x5) 주소가 아니라 그냥 정수라고 판단
        // 단, depth가 0일 때는 그냥 정수일 수도 있으니 패스하지만, 
        // depth가 1 이상인데 값이 작다면 더 이상 포인터가 아님.
        if (ptrVal.compare(0x10000) < 0) {
            // 주소가 아니라 '값(Value)'에 도달함
            return `Value: ${ptrVal.toInt32()} (0x${ptrVal.toString(16)})`;
        }

        // 3. 메모리 읽기 시도 (try-catch로 안전하게)
        try {
            // 일단 읽히는지 테스트 (1바이트 읽기)
            ptrVal.readU8(); 

            // 여기까지 오면 '유효한 주소'임.
            // 문자열인지 확인
            try {
                const str = ptrVal.readUtf8String();
                // 출력 가능한 문자열이고 길이가 적당하면 문자열로 판단
                if (str && str.length > 1 && str.length < 1000 && /^[\x20-\x7E]*$/.test(str)) {
                    return `String: "${str}"`;
                }
            } catch(e) {}

            // 문자열이 아니라면, 이 안에 '또 다른 주소'가 들어있는지 확인 (다음 단계로 진입)
            // 64비트 포인터 하나를 읽어봄
            const nextPtr = ptrVal.readPointer();
            
            // ★ 재귀 호출: 읽은 값을 가지고 한 번 더 파고들어감
            // depth 2까지만 가도 이중 포인터 확인 가능 (너무 깊으면 스택 오버플로우 방지 위해 3에서 컷)
            if (depth < 3) {
                const chainResult = probePointer(nextPtr, depth + 1);
                
                // 만약 다음 단계가 'Value'나 'String'이나 유효한 결과라면 체인으로 연결
                if (!chainResult.startsWith("Value: 0x") && !chainResult.includes("NULL")) { // 단순 값이 아니면
                     return `Ptr -> [ ${chainResult} ]`;
                }
                
                // 다음 단계가 그냥 숫자라면, 현재는 [값]을 가진 포인터임
                // 예: int *a (a는 주소, *a는 100)
                return `Ref -> { ${chainResult} }`;
            } else {
                return "Stop (Too Deep)";
            }

        } catch (e) {
            // 읽기 실패하면 주소가 아니라 그냥 거대한 정수 값임
            return `Raw: ${ptrVal.toString()}`;
        }
    }

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            console.log(`\n${C_LEVEL0}[+] Func Call (Auto-Detecting Double Pointers)${C_RST}`);
            
            // 설정한 개수만큼 모든 파라미터 전수 조사
            for (let i = 0; i < ARG_COUNT; i++) {
                let argVal = args[i];
                let label = `Arg[${i}]`;

                // 탐색 시작 (Depth 0)
                // 결과 문자열을 분석해서 색상 입히기
                let result = probePointer(argVal, 0);

                if (result.includes("Ref -> { Ref ->")) {
                     // 이중 포인터 패턴 감지 (Ref inside Ref)
                     console.log(`${C_LEVEL2}    ${label}: ${argVal}  =>  **Double Pointer Detected! ${result}${C_RST}`);
                } else if (result.includes("Ref ->")) {
                     // 단일 포인터
                     console.log(`${C_LEVEL1}    ${label}: ${argVal}  =>  *Single Pointer: ${result}${C_RST}`);
                } else if (result.includes("String")) {
                     // 문자열
                     console.log(`${C_LEVEL1}    ${label}: ${argVal}  =>  ${result}${C_RST}`);
                } else {
                     // 일반 값
                     console.log(`    ${label}: ${argVal}  =>  ${result}`);
                }
            }
        }
    });
}

autoInspect();

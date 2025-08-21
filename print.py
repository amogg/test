# -*- coding: utf-8 -*-

import socket

# --- 사용자 설정 ---
# 프린터 또는 직렬-이더넷 컨버터의 IP 주소
TARGET_IP = '192.168.1.100'
# 프린터나 컨버터가 리스닝하고 있는 TCP 포트
# 일반적인 네트워크 프린터의 Raw 데이터 포트는 9100 입니다.
# 장비 매뉴얼을 확인하여 정확한 포트를 입력하세요.
TARGET_PORT = 9100

def send_at_command(command):
    """
    지정된 IP와 포트로 AT 명령어를 전송하는 함수
    """
    # 전송할 명령어는 바이트(bytes) 형태로 인코딩해야 합니다.
    # AT 명령어는 보통 캐리지 리턴(\r)과 라인 피드(\n)로 끝나야 합니다.
    full_command = (command + '\r\n').encode('utf-8')

    print(f"[*] 대상: {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] 전송할 명령어: {full_command.decode().strip()}")

    # TCP 소켓 생성 (IPv4, TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 타임아웃 설정 (5초)
            s.settimeout(5)

            # 서버(프린터)에 연결
            s.connect((TARGET_IP, TARGET_PORT))
            print("[+] 연결 성공!")

            # 명령어 전송
            s.sendall(full_command)
            print("[+] 명령어 전송 완료.")

            # 프린터로부터 응답 받기 (옵션)
            # 1024 바이트까지 응답을 기다립니다.
            response = s.recv(1024)
            print(f"[+] 응답 수신:\n{response.decode('utf-8', errors='ignore')}")

        except socket.timeout:
            print("[!] 오류: 연결 시간이 초과되었습니다. IP나 포트를 확인하세요.")
        except ConnectionRefusedError:
            print("[!] 오류: 연결이 거부되었습니다. 포트가 닫혀있거나 방화벽 문제일 수 있습니다.")
        except Exception as e:
            print(f"[!] 알 수 없는 오류 발생: {e}")

if __name__ == "__main__":
    # 예시: 모뎀 상태를 확인하는 기본 AT 명령어
    send_at_command('AT')

    print("-" * 20)

    # 예시: 모뎀 정보 확인 명령어
    send_at_command('ATI')

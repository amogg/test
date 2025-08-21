# -*- coding: utf-8 -*-

import socket
import time

# --- 사용자 설정 ---
# 제어하려는 프린터의 IP 주소
PRINTER_IP = '192.168.1.200'
# 프린터의 Raw 데이터 수신 포트 (일반적으로 9100)
PRINTER_PORT = 9100

def send_printer_command(command_bytes):
    """
    지정된 IP와 포트로 프린터 제어 명령어를 전송하는 함수
    :param command_bytes: 전송할 명령어 (bytes 형태)
    """
    print(f"[*] 대상: {PRINTER_IP}:{PRINTER_PORT}")
    # 화면에 표시하기 위해 디코딩 (오류 무시)
    print(f"[*] 전송할 명령어 (일부): {command_bytes.decode('utf-8', errors='ignore').strip()[:50]}...")

    # TCP 소켓 생성 (IPv4, TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 타임아웃 설정 (5초)
            s.settimeout(5)

            # 프린터에 연결
            s.connect((PRINTER_IP, PRINTER_PORT))
            print("[+] 연결 성공!")

            # 명령어 전송
            s.sendall(command_bytes)
            print("[+] 명령어 전송 완료.")

            # 프린터로부터 응답 받기 (PJL 명령어는 보통 응답이 있음)
            # 1024 바이트까지 응답을 기다립니다.
            response = s.recv(1024)
            print(f"[+] 응답 수신:\n{response.decode('utf-8', errors='ignore')}")

        except socket.timeout:
            print("[!] 오류: 연결 시간이 초과되었습니다. IP나 포트, 프린터 상태를 확인하세요.")
        except ConnectionRefusedError:
            print("[!] 오류: 연결이 거부되었습니다. 포트가 닫혀있거나 방화벽 문제일 수 있습니다.")
        except Exception as e:
            print(f"[!] 알 수 없는 오류 발생: {e}")

if __name__ == "__main__":
    # --- 예제 명령어 ---
    # 파이썬에서 b'...'는 바이트 문자열을 의미합니다.
    # \x1b는 16진수 1B로, 아스키(ASCII) 코드의 ESC(Escape) 문자를 의미합니다.

    # 0. PJL 예제 - 프린터 지원 언어 확인하기
    # @PJL INFO ID 명령어를 보내면 프린터의 ID와 지원 언어(LANGUAGES) 정보를 얻을 수 있습니다.
    print("--- 0. 프린터 지원 언어 확인 테스트 ---")
    pjl_info_id_command = b'\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X'
    send_printer_command(pjl_info_id_command)
    time.sleep(2) # 다음 명령어를 위해 잠시 대기

    # 1. PJL (Printer Job Language) 예제 - 프린터 상태 정보 요청
    # PJL 명령어는 보통 사람이 읽을 수 있는 텍스트 형태입니다.
    # <ESC>%-12345X 로 시작하여 PJL 모드로 진입하고, 끝날 때 다시 호출하여 종료합니다.
    print("\n--- 1. PJL 상태 정보 요청 테스트 ---")
    pjl_status_command = b'\x1b%-12345X@PJL INFO STATUS\r\n\x1b%-12345X'
    send_printer_command(pjl_status_command)
    time.sleep(2) # 다음 명령어를 위해 잠시 대기

    # 2. PCL (Printer Command Language) 예제 - 프린터 리셋 및 텍스트 인쇄
    # PCL 명령어는 보통 ESC 문자로 시작하는 제어 코드의 조합입니다.
    print("\n--- 2. PCL 명령어 전송 테스트 ---")
    # <ESC>E : 프린터 리셋
    # (s0p12h0s3b4099T : 폰트 설정 (Courier, 12 cpi)
    # Hello, PCL! : 인쇄할 텍스트
    # \r\n : 줄바꿈
    pcl_command = b'\x1bE(s0p12h0s3b4099THello, PCL!\r\n\x1bE'
    send_printer_command(pcl_command)
    time.sleep(2)

    # 3. PostScript (PS) 예제 - "Hello, PostScript!" 텍스트 인쇄
    # PostScript는 페이지 기술 언어로, 프로그램과 유사한 구조를 가집니다.
    print("\n--- 3. PostScript 명령어 전송 테스트 ---")
    ps_command = b"""%!PS
/Courier findfont 20 scalefont setfont
72 720 moveto
(Hello, PostScript!) show
showpage
"""
    send_printer_command(ps_command)


# -*- coding: utf-8 -*-

import socket
import time
import re

# --- 사용자 설정 ---
# 제어하려는 프린터의 IP 주소
PRINTER_IP = '192.168.1.200'
# 프린터의 Raw 데이터 수신 포트 (일반적으로 9100)
PRINTER_PORT = 9100

def pjl_download_file(file_path, save_as):
    """
    PJL을 사용하여 프린터에서 파일을 다운로드하는 함수
    :param file_path: 프린터 내의 파일 경로 (예: "/pjl/config.ini")
    :param save_as: 로컬에 저장할 파일 이름
    """
    # --- 1단계: 파일 크기 조회 ---
    print(f"\n--- 1단계: 파일 크기 조회 시작 ({file_path}) ---")
    query_command_str = f'@PJL FSQUERY NAME="{file_path}"'
    uel_prefix = b'\x1b%-12345X'
    full_query_command = uel_prefix + query_command_str.encode('utf-8') + b'\r\n' + uel_prefix

    file_size = -1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(10)
            s.connect((PRINTER_IP, PRINTER_PORT))
            s.sendall(full_query_command)
            response = s.recv(4096).decode('utf-8', errors='ignore')
            
            print(f"[+] 크기 조회 응답 수신:\n{response.strip()}")

            # 정규표현식을 사용해 'SIZE=' 뒤의 숫자(파일 크기)를 찾음
            match = re.search(r'SIZE=(\d+)', response)
            if match:
                file_size = int(match.group(1))
                print(f"[*] 파일 크기 확인: {file_size} bytes")
            else:
                print(f"[!] 오류: 응답에서 파일 크기를 찾을 수 없습니다. 파일 경로가 올바른지 확인하세요.")
                return False
        except Exception as e:
            print(f"[!] 오류: 파일 크기 조회 중 오류 발생: {e}")
            return False

    # --- 2단계: 파일 다운로드 ---
    if file_size < 0:
        return False

    print(f"\n--- 2단계: 파일 다운로드 시작 ({file_path}) ---")
    download_command_str = f'@PJL FSDOWNLOAD FORMAT:BINARY SIZE={file_size} NAME="{file_path}"'
    full_download_command = uel_prefix + download_command_str.encode('utf-8') + b'\r\n'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 넉넉하게 타임아웃을 60초로 늘림
            s.settimeout(60) 
            s.connect((PRINTER_IP, PRINTER_PORT))
            s.sendall(full_download_command)
            print("[+] 다운로드 요청 전송 완료. 데이터 수신을 시작합니다...")

            # 프린터가 연결을 닫을 때까지 모든 데이터를 수신
            received_data = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    # chunk가 비어있으면 상대방이 연결을 닫았다는 의미
                    print("[*] 프린터가 연결을 종료했습니다. 데이터 수신 완료.")
                    break
                received_data += chunk
            
            print(f"[*] 총 {len(received_data)} bytes 데이터 수신 완료.")

            # 수신된 데이터가 있는지 확인 후 저장
            if len(received_data) > 0:
                # 'wb' 모드(바이너리 쓰기)로 파일을 저장
                with open(save_as, 'wb') as f:
                    f.write(received_data)
                print(f"\n[+] 성공: 파일 '{save_as}' ({len(received_data)} bytes) 저장을 완료했습니다.")
                
                # 예상 크기와 실제 수신 크기가 다른 경우 경고 메시지 표시
                if len(received_data) != file_size:
                    print(f"[!] 경고: 예상 크기({file_size} bytes)와 실제 수신 크기({len(received_data)} bytes)가 다릅니다. 파일이 불완전할 수 있습니다.")
                return True
            else:
                print("\n[!] 오류: 다운로드된 데이터가 없습니다.")
                return False

        except socket.timeout:
            print("[!] 오류: 타임아웃 발생. 프린터가 응답하지 않거나 네트워크에 문제가 있을 수 있습니다.")
            return False
        except Exception as e:
            print(f"[!] 다운로드 중 오류 발생: {e}")
            return False

if __name__ == "__main__":
    # ⚠️ 중요: 이 변수 값을 실제 다운로드할 파일 경로로 변경해야 합니다.
    # 이 경로는 PJL FSDIRLIST 명령어로 미리 확인해야 합니다.
    printer_file_to_download = "/pjl/config.ini" 
    
    # 로컬 컴퓨터에 저장될 파일 이름
    local_file_name = "downloaded_from_printer.ini"

    # 함수를 호출하여 파일 다운로드 시도
    pjl_download_file(printer_file_to_download, local_file_name)

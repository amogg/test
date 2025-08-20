# -*- coding: utf-8 -*-

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
import time

# --- 사용자 설정 변수 ---
# PLC의 IP 주소를 입력하세요.
PLC_IP = '192.168.1.10'
# Modbus TCP 기본 포트는 502입니다.
PLC_PORT = 502
# Modbus 슬레이브 ID (일반적으로 1)
SLAVE_ID = 1

def run_modbus_test():
    """
    PLC에 Modbus TCP로 연결하여 데이터를 읽고 쓰는 함수
    """
    # Modbus TCP 클라이언트 생성
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    try:
        # PLC에 연결 시도
        if not client.connect():
            print(f" [오류] PLC({PLC_IP}:{PLC_PORT})에 연결할 수 없습니다.")
            print("        1. PLC의 전원 및 네트워크 연결을 확인하세요.")
            print("        2. QJ71E71-100 모듈의 Modbus TCP 서버 설정이 올바른지 확인하세요.")
            return

        print(f" [성공] PLC({PLC_IP}:{PLC_PORT})에 연결되었습니다.")
        time.sleep(1) # 안정적인 통신을 위한 잠시 대기

        # 1. 데이터 읽기 (Read Holding Registers)
        # --------------------------------------------------------------------
        # 읽기를 시작할 주소 (예: D100 레지스터가 Modbus 주소 0에 매핑된 경우)
        # PLC의 Modbus 주소 맵을 반드시 확인해야 합니다.
        read_start_address = 0
        # 읽어올 레지스터 개수 (워드 단위, 16비트)
        read_register_count = 10

        print(f"\n [읽기 시도] 주소 {read_start_address}부터 {read_register_count}개의 홀딩 레지스터를 읽습니다.")

        # read_holding_registers 함수 호출
        # unit=SLAVE_ID는 슬레이브 ID를 지정합니다.
        response = client.read_holding_registers(read_start_address, read_register_count, unit=SLAVE_ID)

        # 응답 확인
        if response.isError():
            print(f" [읽기 오류] Modbus 오류가 발생했습니다: {response}")
        elif not response.registers:
            print(" [읽기 오류] 응답이 비어있습니다.")
        else:
            # 성공적으로 읽었을 경우, 결과 출력
            print(" [읽기 성공] 읽어온 데이터:")
            # response.registers는 값의 리스트입니다.
            for i, value in enumerate(response.registers):
                print(f"  - 주소 {read_start_address + i}: {value}")

        time.sleep(1)

        # 2. 데이터 쓰기 (Write Single Register / Write Multiple Registers)
        # --------------------------------------------------------------------
        # ⚠️ 경고: 실제 장비에 영향을 줄 수 있으니, 안전한 주소에만 쓰기 작업을 테스트하세요.

        # 2-1. 단일 레지스터 쓰기
        write_single_address = 20
        value_to_write = 1234

        print(f"\n [쓰기 시도] 주소 {write_single_address}에 단일 값 {value_to_write}을 씁니다.")
        # write_register 함수 호출
        response = client.write_register(write_single_address, value_to_write, unit=SLAVE_ID)

        if response.isError():
            print(f" [쓰기 오류] 단일 레지스터 쓰기 중 오류 발생: {response}")
        else:
            print(" [쓰기 성공] 단일 레지스터에 값을 성공적으로 썼습니다.")
            # 확인을 위해 방금 쓴 값 다시 읽기
            read_back = client.read_holding_registers(write_single_address, 1, unit=SLAVE_ID)
            if not read_back.isError():
                print(f"  - 확인 읽기: 주소 {write_single_address}의 값 = {read_back.registers[0]}")

        time.sleep(1)

        # 2-2. 여러 레지스터 쓰기
        write_multiple_address = 30
        values_to_write = [10, 20, 30, 40, 50] # 리스트 형태로 값 준비

        print(f"\n [쓰기 시도] 주소 {write_multiple_address}부터 여러 값 {values_to_write}을 씁니다.")
        # write_registers 함수 호출
        response = client.write_registers(write_multiple_address, values_to_write, unit=SLAVE_ID)

        if response.isError():
            print(f" [쓰기 오류] 여러 레지스터 쓰기 중 오류 발생: {response}")
        else:
            print(" [쓰기 성공] 여러 레지스터에 값을 성공적으로 썼습니다.")
            # 확인을 위해 방금 쓴 값들 다시 읽기
            read_back = client.read_holding_registers(write_multiple_address, len(values_to_write), unit=SLAVE_ID)
            if not read_back.isError():
                print(f"  - 확인 읽기: 주소 {write_multiple_address}부터의 값 = {read_back.registers}")


    except ModbusException as e:
        print(f" [심각한 오류] Modbus 통신 중 예외가 발생했습니다: {e}")
    except Exception as e:
        print(f" [심각한 오류] 알 수 없는 오류가 발생했습니다: {e}")
    finally:
        # 모든 작업이 끝나면 반드시 연결을 닫아줍니다.
        if client.is_socket_open():
            client.close()
            print("\n [연결 종료] PLC와의 연결을 닫았습니다.")

if __name__ == "__main__":
    run_modbus_test()

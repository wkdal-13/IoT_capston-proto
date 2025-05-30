# tplink.py

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

class TPLinkScanner:
    """
    TP-Link 공유기의 웹 관리 페이지에 접속해
    보안 설정(SSID 숨김, 무선 보안, WPS, SPI 방화벽 등)을 점검한 뒤
    (레벨, 메시지) 튜플 리스트로 반환합니다.
    """
    def __init__(self, router_ip: str, headless: bool = True):
        self.router_ip = router_ip
        self.base_url = f"http://{router_ip}"
        # ChromeOptions 설정
        self.options = Options()
        if headless:
            self.options.add_argument("--headless")
            self.options.add_argument("--no-sandbox")
            self.options.add_argument("--disable-dev-shm-usage")
        self.driver = None
        self.results = []

    def start_driver(self):
        """Chrome WebDriver를 시작하고 암묵적 대기 설정."""
        try:
            self.driver = webdriver.Chrome(options=self.options)
            self.driver.implicitly_wait(10)
        except Exception as e:
            self.results.append(("danger", f"❌ 드라이버 시작 실패: {e}"))
            self.driver = None

    def stop_driver(self):
        """WebDriver를 종료."""
        try:
            if self.driver:
                self.driver.quit()
        except Exception as e:
            self.results.append(("warning", f"⚠️ 드라이버 종료 실패: {e}"))

    def switch_to_frame(self, frame_name: str):
        """지정된 이름의 frame으로 전환."""
        try:
            self.driver.switch_to.default_content()
            WebDriverWait(self.driver, 10).until(
                EC.frame_to_be_available_and_switch_to_it((By.NAME, frame_name))
            )
        except Exception as e:
            self.results.append(("warning", f"⚠️ 프레임 전환 실패 ({frame_name}): {e}"))

    def click_menu(self, menu_id: str):
        """왼쪽 메뉴에서 ID로 지정된 항목을 클릭."""
        try:
            self.switch_to_frame("bottomLeftFrame")
            btn = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.ID, menu_id))
            )
            btn.click()
        except Exception as e:
            self.results.append(("warning", f"⚠️ 메뉴 클릭 실패 ({menu_id}): {e}"))

    def check_element_selected(self,
                               element_id: str,
                               expected_selected: bool,
                               success_msg: str,
                               fail_msg: str):
        """mainFrame에서 ID로 찾은 요소의 선택 상태를 확인해 메시지 추가."""
        try:
            self.switch_to_frame("mainFrame")
            elem = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, element_id))
            )
            if elem.is_selected() == expected_selected:
                self.results.append(("success", success_msg))
            else:
                self.results.append(("warning", fail_msg))
        except Exception as e:
            self.results.append(("warning", f"⚠️ {success_msg or fail_msg} 확인 실패: {e}"))

    def run_security_check(self, admin_password: str = "") -> list[tuple[str,str]]:
        """
        1) 드라이버 시작
        2) 로그인 (비밀번호 입력)
        3) 여러 보안 설정 점검
        4) 드라이버 종료 후 결과 리스트 반환
        """
        self.start_driver()
        try:
            if not self.driver:
                raise RuntimeError("WebDriver 시작 실패")

            # — 로그인 —
            self.driver.get(self.base_url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "pcPassword"))
            )
            pwd_in = self.driver.find_element(By.ID, "pcPassword")
            pwd_in.send_keys(admin_password)
            pwd_in.send_keys(Keys.ENTER)
            time.sleep(2)

            # 1. SSID 숨김 여부
            self.click_menu("menu_wl")
            self.check_element_selected(
                element_id="ssidBroadcast",
                expected_selected=False,
                success_msg="✅ SSID 숨김 설정 완료",
                fail_msg="⚠️ SSID 브로드캐스트 사용 중 (숨김 권장)"
            )

            # 2. 무선 보안(Personal) 설정
            self.click_menu("menu_wlsec")
            try:
                self.switch_to_frame("mainFrame")
                radios = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_all_elements_located((By.NAME, "secType"))
                )
                sel = next((r.get_attribute("value") for r in radios if r.is_selected()), None)
                if sel == "3":
                    self.results.append(("success", "✅ WPA2/WPA3-개인(권장) 적용됨"))
                elif sel == "0":
                    self.results.append(("danger", "❌ 무선 보안 비활성화 (심각한 위험)"))
                else:
                    self.results.append(("warning", f"⚠️ 약한 보안 설정: 유형 {sel}"))
            except Exception as e:
                self.results.append(("warning", f"⚠️ 무선 보안 상태 확인 실패: {e}"))

            # 3. WPS 활성화 여부 (버튼 라벨 반대로 동작)
            self.click_menu("menu_wlqss")
            try:
                self.switch_to_frame("mainFrame")
                wps_btn = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.ID, "qssSwitch"))
                )
                label = wps_btn.get_attribute("value") or ""
                if "사용" in label and "안함" not in label:
                    self.results.append(("success", "✅ WPS 비활성화 (양호)"))
                else:
                    self.results.append(("danger", "❌ WPS 활성화 상태 (위험)"))
            except Exception as e:
                self.results.append(("warning", f"⚠️ WPS 상태 확인 실패: {e}"))

            # 4. SPI 방화벽
            self.click_menu("menu_security")
            self.check_element_selected(
                element_id="enable_spi",
                expected_selected=True,
                success_msg="✅ SPI 방화벽 활성화됨",
                fail_msg="❌ SPI 방화벽 비활성화 (위험)"
            )

            # 5. WAN Ping 차단
            self.click_menu("menu_ddos")
            self.check_element_selected(
                element_id="wanPingFilter",
                expected_selected=True,
                success_msg="✅ WAN Ping 차단 활성화됨",
                fail_msg="⚠️ WAN Ping 응답 허용 중"
            )

            # 6. 무선 MAC 필터링
            self.click_menu("menu_wl")
            self.click_menu("menu_wlacl")
            self.check_element_selected(
                element_id="acl_en",
                expected_selected=True,
                success_msg="✅ 무선 MAC 필터링 사용 중",
                fail_msg="⚠️ 무선 MAC 필터링 미사용"
            )

            # 7. 게스트 네트워크 비활성화 여부
            self.click_menu("menu_wlguest")
            try:
                self.switch_to_frame("mainFrame")
                guest_off = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.ID, "guestDis"))
                )
                if guest_off.is_selected():
                    self.results.append(("success", "✅ 게스트 네트워크 비활성화됨"))
                else:
                    self.results.append(("danger", "❌ 게스트 네트워크 허용됨 (위험)"))
            except Exception as e:
                self.results.append(("warning", f"⚠️ 게스트 네트워크 확인 실패: {e}"))

        except Exception as e:
            self.results.append(("danger", f"❌ 점검 중단: {e}"))
        finally:
            self.stop_driver()
            return self.results


def inspect_router(router_ip: str,
                   username: str | None = None,
                   password: str = "") -> list[tuple[str,str]]:
    """
    app.py에서 호출할 수 있는 래퍼 함수.
    :param router_ip: 공유기 관리 페이지 IP
    :param username: TP-Link는 사용하지 않으므로 무시
    :param password: 관리자 비밀번호
    :return: [('success','…'), ('warning','…'), ...] 형태의 결과 리스트
    """
    scanner = TPLinkScanner(router_ip)
    return scanner.run_security_check(password)


if __name__ == "__main__":
    # 단독 실행 시 간단 테스트
    import sys
    if len(sys.argv) < 2:
        print("사용법: python tplink.py <라우터 IP> [관리자 비밀번호]")
        sys.exit(1)

    ip = sys.argv[1]
    pwd = sys.argv[2] if len(sys.argv) >= 3 else ""
    for level, msg in inspect_router(ip, None, pwd):
        print(f"{level.upper():<8} {msg}")

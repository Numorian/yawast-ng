import time
from typing import Dict, List, Optional

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from webdriver_manager.chrome import ChromeDriverManager

from yawast.shared import output

COMMON_USER_FIELDS = [
    "username",
    "user",
    "email",
    "login",
    "userid",
    "user_name",
    "email_address",
]
COMMON_PASS_FIELDS = ["password", "pass", "passwd", "pwd"]
COMMON_SUBMIT_BUTTONS = ["login", "submit", "signin", "log-in", "sign-in"]


class LoginFormNotFound(Exception):
    """Exception raised when login form is not found."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def login_and_get_auth(
    url: str, username: str, password: str
) -> Dict[str, Optional[dict]]:
    """
    Attempts to login to a website using Selenium and returns session cookies and Authorization header if present.
    :param url: The URL to start at (login page or homepage).
    :param username: The username/email to use.
    :param password: The password to use.
    :param login_url: Optional explicit login page URL to visit before filling the form.
    :return: Dict with 'cookies', 'header', and 'error' keys.
    """
    options = webdriver.ChromeOptions()
    options.add_argument("headless")
    options.add_argument("incognito")
    options.add_argument("disable-dev-shm-usage")
    options.add_argument("no-sandbox")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.accept_insecure_certs = True

    driver = webdriver.Chrome(
        service=ChromeService(ChromeDriverManager().install()), options=options
    )

    try:
        driver.get(url)
        time.sleep(2)  # Let JS-heavy pages load

        user_field = _find_element(driver, COMMON_USER_FIELDS)
        pass_field = _find_element(driver, COMMON_PASS_FIELDS)

        # If login fields not found, try to find and click a login link, then search again
        if not user_field or not pass_field:
            login_link = _find_login_link(driver)

            output.debug(
                f"Login link found: {login_link.get_attribute('outerHTML') if login_link else 'None'}"
            )

            if login_link:
                login_link.click()
                time.sleep(2)  # Wait for navigation
                user_field = _find_element(driver, COMMON_USER_FIELDS)
                pass_field = _find_element(driver, COMMON_PASS_FIELDS)

        if not user_field or not pass_field:
            raise LoginFormNotFound("Could not find login form fields.")

        output.debug(f"Found user field: {user_field.get_attribute('outerHTML')}")
        output.debug(f"Found pass field: {pass_field.get_attribute('outerHTML')}")

        user_field.clear()
        user_field.send_keys(username)
        pass_field.clear()
        pass_field.send_keys(password)

        # Try clicking a submit button
        btn = _find_element(driver, COMMON_SUBMIT_BUTTONS, type="submit")
        if not btn:
            btn = _find_element(driver, COMMON_SUBMIT_BUTTONS, type="button")

        if btn:
            btn.click()
        else:
            pass_field.submit()

        time.sleep(3)  # Wait for login to process

        # Detect likely error messages after login attempt
        error_message = _detect_login_error(driver)

        cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
        header = None
        # Try to extract Authorization header from localStorage/sessionStorage if present
        for storage in ["localStorage", "sessionStorage"]:
            for key in driver.execute_script(f"return Object.keys(window.{storage});"):
                value = driver.execute_script(
                    f"return window.{storage}.getItem('{key}');"
                )
                if key.lower() == "authorization" or "token" in key.lower():
                    header = {key: value}
                    break
            if header:
                break

        output.debug(
            f"Login process completed. Found {len(cookies)} cookies and {len(header) if header else 0} headers."
        )

        return {"cookies": cookies, "header": header, "error": error_message}
    finally:
        driver.quit()


def _find_element(
    driver: WebDriver, names: List[str], type: str = None
) -> Optional[WebElement]:
    button_search = ""
    if type is not None:
        if type == "button":
            button_search = "[@type='button']"
        elif type == "submit":
            button_search = "[@type='submit']"

    for name in names:
        # Try by name, id, placeholder
        for attr in ["name", "id", "placeholder"]:
            try:
                el = driver.find_element(
                    By.XPATH,
                    f'//input[contains(translate(@{attr}, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "{name}")]{button_search}',
                )
                if el.is_displayed():
                    return el
            except Exception as e:
                pass

    return None


def _find_parent_form(element: WebElement) -> Optional[WebElement]:
    parent = element
    for _ in range(5):
        try:
            parent = parent.find_element("xpath", "..")
            if parent.tag_name.lower() == "form":
                return parent
        except Exception:
            break
    return None


def _find_login_link(driver: WebDriver) -> Optional[WebElement]:
    """
    Attempts to find a link to a login page by common link texts.
    """
    login_texts = [
        "login",
        "sign in",
        "log in",
        "signin",
        "log-in",
        "sign-in",
        "account",
    ]
    for text in login_texts:
        try:
            el = driver.find_element(
                "xpath",
                f'//a[contains(translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "{text}")]',
            )
            if el.is_displayed():
                return el
        except Exception:
            pass
    return None


def _detect_login_error(driver: WebDriver) -> Optional[str]:
    """
    Searches the page for common login error messages and returns the first found, or None.
    """
    error_keywords = [
        "invalid password",
        "incorrect password",
        "invalid username",
        "incorrect username",
        "login failed",
        "authentication failed",
        "invalid credentials",
        "incorrect credentials",
        "try again",
        "unable to login",
        "account locked",
        "error",
        "failed",
        "not recognized",
        "wrong password",
        "wrong username",
        "access denied",
        "unauthorized",
    ]
    # Search visible text in common error containers
    selectors = [
        '//div[contains(@class, "error") or contains(@class, "alert") or contains(@class, "message")]',
        '//span[contains(@class, "error") or contains(@class, "alert") or contains(@class, "message")]',
        '//p[contains(@class, "error") or contains(@class, "alert") or contains(@class, "message")]',
        '//li[contains(@class, "error") or contains(@class, "alert") or contains(@class, "message")]',
        '//*[contains(@id, "error") or contains(@id, "alert") or contains(@id, "message")]',
    ]
    for selector in selectors:
        try:
            elements = driver.find_elements("xpath", selector)
            for el in elements:
                if not el.is_displayed():
                    continue
                text = el.text.strip().lower()
                for keyword in error_keywords:
                    if keyword in text:
                        return el.text.strip()
        except Exception:
            pass
    # Fallback: search all visible text for error keywords
    try:
        body_text = driver.find_element("tag name", "body").text.lower()
        for keyword in error_keywords:
            if keyword in body_text:
                return keyword
    except Exception:
        pass
    return None

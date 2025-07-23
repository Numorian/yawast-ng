from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.webdriver import WebDriver
from webdriver_manager.chrome import ChromeDriverManager

from yawast.scanner.session import Session


def get_selenium_driver(session: Session, uri: str) -> WebDriver:
    options = webdriver.ChromeOptions()
    options.add_argument("headless")
    options.add_argument("incognito")
    options.add_argument("disable-dev-shm-usage")
    options.add_argument("no-sandbox")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.accept_insecure_certs = True

    # if we have a proxy set, use that
    if session.args.proxy:
        proxy = webdriver.Proxy()
        proxy.http_proxy = f"http://#{session.args.proxy}"
        proxy.ssl_proxy = f"http://#{session.args.proxy}"
        options.proxy = proxy

    driver = webdriver.Chrome(
        service=ChromeService(ChromeDriverManager().install()), options=options
    )
    driver.get(uri)

    return driver

import secrets
import time
from typing import List

import selenium
from selenium import webdriver

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.result import Result
from yawast.scanner.session import Session
from yawast.shared import output
from yawast.shared import utils

timing = {True: [], False: []}


def check_resp_user_enum(spinner, session: Session) -> List[Result]:
    global timing
    results = []
    element_name = None

    pass_reset_page = session.args.pass_reset_page
    if pass_reset_page:
        user = session.args.user
        spinner.stop()
        if user is None:
            user = utils.prompt("What is a valid user? ")

        try:
            # checks for user enum via differences in response
            # run each test 5 times to collect timing info
            good_user_res, good_user_img = fill_form_get_body(
                session, pass_reset_page, user, True, True
            )
            fill_form_get_body(session, pass_reset_page, user, True, False)
            fill_form_get_body(session, pass_reset_page, user, True, False)
            fill_form_get_body(session, pass_reset_page, user, True, False)
            fill_form_get_body(session, pass_reset_page, user, True, False)

            bad_user_res, bad_user_img = fill_form_get_body(
                session,
                pass_reset_page,
                secrets.token_hex() + "@invalid.example.com",
                False,
                True,
            )
            fill_form_get_body(
                session,
                pass_reset_page,
                secrets.token_hex() + "@invalid.example.com",
                False,
                False,
            )
            fill_form_get_body(
                session,
                pass_reset_page,
                secrets.token_hex() + "@invalid.example.com",
                False,
                False,
            )
            fill_form_get_body(
                session,
                pass_reset_page,
                secrets.token_hex() + "@invalid.example.com",
                False,
                False,
            )
            fill_form_get_body(
                session,
                pass_reset_page,
                secrets.token_hex() + "@invalid.example.com",
                False,
                False,
            )

            # check for difference in response
            if good_user_res != bad_user_res:
                results.append(
                    Result.from_evidence(
                        Evidence(
                            url=pass_reset_page,
                            request=None,
                            response=None,
                            custom={
                                "good_response": good_user_res,
                                "bad_response": bad_user_res,
                                "good_response_img": good_user_img,
                                "bad_response_img": bad_user_img,
                            },
                        ),
                        f"Password Reset: Possible User Enumeration - Difference in Response",
                        Vulnerabilities.HTTP_USER_ENUMERATION,
                    )
                )

            # check for timing issues
            valid_average = sum(timing[True]) / len(timing[True])
            invalid_average = sum(timing[False]) / len(timing[False])
            timing_diff = abs(valid_average - invalid_average)
            if timing_diff > 10:
                # in this case, we have a difference in the averages of greater than 10ms.
                # this is an arbitrary number, but 10ms is likely good enough
                results.append(
                    Result.from_evidence(
                        Evidence(
                            url=pass_reset_page,
                            request=None,
                            response=None,
                            custom={
                                "difference": timing_diff,
                                "valid_1": timing[True][0],
                                "valid_2": timing[True][1],
                                "valid_3": timing[True][2],
                                "valid_4": timing[True][3],
                                "valid_5": timing[True][4],
                                "invalid_1": timing[False][0],
                                "invalid_2": timing[False][1],
                                "invalid_3": timing[False][2],
                                "invalid_4": timing[False][3],
                                "invalid_5": timing[False][4],
                            },
                        ),
                        f"Password Reset: Possible User Enumeration - Difference in Timing",
                        Vulnerabilities.HTTP_USER_ENUMERATION_TIMING,
                    )
                )
        except selenium.common.exceptions.WebDriverException as e:
            output.error("Selenium error encountered: " + e.msg)
        except ValueError as e:
            output.error(
                "Unable to find a matching element to perform the User Enumeration via Password Reset: "
                + str(e)
            )
        except Exception as e:
            output.error(
                "Failed to execute Password Reset Page User Enumeration: " + str(e)
            )

        spinner.start()

    return results


def fill_form_get_body(session: Session, uri, user, valid, log_output):
    global timing

    options = webdriver.ChromeOptions()
    options.add_argument("headless")
    options.add_argument("incognito")
    options.add_argument("disable-dev-shm-usage")
    options.add_argument("no-sandbox")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    # if we have a proxy set, use that
    if session.args.proxy:
        proxy = webdriver.Proxy()
        proxy.http_proxy = f"http://#{session.args.proxy}"
        proxy.ssl_proxy = f"http://#{session.args.proxy}"
        caps = webdriver.DesiredCapabilities.CHROME.copy()
        caps["acceptInsecureCerts"] = True
        caps["proxy"] = proxy
    else:
        caps = webdriver.DesiredCapabilities.CHROME.copy()
        caps["acceptInsecureCerts"] = True

    driver = webdriver.Chrome(chrome_options=options, desired_capabilities=caps)
    driver.get(uri)

    # find the page form element - this is going to be a best effort thing, and may not always be right
    element = find_user_field(driver)

    # the element may not actually be visible yet (heavy JS pages)
    # so, we'll go into a loop for a few seconds to see if it'll show up
    counter = 0
    if not element.is_displayed():
        while not element.is_displayed():
            time.sleep(0.5)
            counter += 1
            if counter > 20:
                break

    element.send_keys(user)

    beginning_time = time.clock()
    element.submit()
    end_time = time.clock()
    timing[valid] += [(end_time - beginning_time) * 1000]

    res = driver.page_source
    img = driver.get_screenshot_as_base64()

    driver.close()

    return res, img


def find_user_field(driver):
    # find the page form element - this is going to be a best effort thing, and may not always be right
    element = find_element(driver, "user_login")
    if element:
        return element

    element = find_element(driver, "email")
    if element:
        return element

    element = find_element(driver, "email_address")
    if element:
        return element

    element = find_element(driver, "forgetPasswordEmailOrUsername")
    if element:
        return element

    element = find_element(driver, "username")
    if element:
        return element

    element = find_element(driver, "user")
    if element:
        return element

    # if we got here, it means that we don't have an element we know about, so we have to prompt
    if element is None:
        print(
            "Unable to find a known element to enter the user name. Please identify the proper element."
        )
        print(
            "If this element seems to be common, please request that it be added: https://github.com/adamcaudill/yawast/issues"
        )
        name = utils.prompt("What is the user/email entry element name? ")
        element = find_element(driver, name)
        if element:
            return element

    raise ValueError("No matching element found.")


def find_element(driver, name):
    ret = None

    # first, check by name
    try:
        ret = driver.find_element_by_name(name)
    except:
        pass

    if not ret:
        # next, maybe it's id instead of name
        try:
            ret = driver.find_element_by_id(name)
        except:
            pass

    return ret

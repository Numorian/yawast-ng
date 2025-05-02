#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.


def is_unsafe_form(soup, field):
    """Detect if the form containing the field has buttons with dangerous actions or password fields."""
    if soup is None:
        return False
    danger_words = [
        "reset",
        "delete",
        "change password",
        "remove",
        "disable",
        "drop",
        "clear",
    ]
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all("input")
        input_names = [i.get("name") for i in inputs if i.get("name")]
        if field in input_names:
            # Exclude if any input is of type password
            if any(inp.get("type", "").lower() == "password" for inp in inputs):
                return True
            # Check all buttons and submit inputs
            for btn in form.find_all(["button", "input"]):
                # For <button> tags, check text
                if btn.name == "button" and btn.text:
                    text = btn.text.lower()
                    if any(word in text for word in danger_words):
                        return True
                # For <input type=submit/button/reset>, check value and type
                if btn.name == "input":
                    btn_type = btn.get("type", "").lower()
                    value = btn.get("value", "").lower()
                    if any(word in value for word in danger_words):
                        return True
                    if btn_type in danger_words:
                        return True
    return False


def is_unsafe_link(href: str, description: str) -> bool:
    """
    Check for strings that indicate an unsafe link
    :param href:
    :param description:
    :return:
    """
    unsafe_fragments = [
        "logoff",
        "log off",
        "log_off",
        "logout",
        "log out",
        "log_out",
        "delete",
        "destroy",
    ]

    try:
        description = str(description).lower() if description is not None else ""
        href = str(href).lower()
        for frag in unsafe_fragments:
            if frag in href or frag in description:
                return True
    except Exception:
        pass
    return False

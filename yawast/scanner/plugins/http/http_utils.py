from requests import Response

from yawast.shared import utils


def is_text(res: Response) -> bool:
    """
    Returns True if the body is HTML, or at least seems like text
    :param res:
    :return:
    """
    has_text = False

    if len(res.content) == 0:
        # don't bother with these, if the body is empty
        has_text = False
    elif "Content-Type" in res.headers and "text/html" in res.headers["Content-Type"]:
        # it's HTML, go
        has_text = True
    elif "Content-Type" not in res.headers:
        # this is something, but the server doesn't tell us what
        # so, we will check to see if if we can treat it like text
        if utils.is_printable_str(res.content):
            has_text = True

    return has_text

import inspect
import logging
import shutil
import sys
import textwrap
import traceback
from inspect import FrameInfo
from multiprocessing.util import get_logger
from threading import Lock
from typing import cast

from colorama import init, Fore, Style

from yawast.reporting import reporter
from yawast.shared import utils

_no_colors = False
_init = False
_wrapper = None
_debug = False
_logger = None
_lock = Lock()


def setup(enable_debug: bool, no_colors: bool):
    global _no_colors, _init, _wrapper, _debug, _logger

    _init = True

    _wrapper = textwrap.TextWrapper()
    width = shutil.get_terminal_size().columns
    _wrapper.width = width if width > 0 else 80
    _wrapper.subsequent_indent = "\t\t\t\N{DOWNWARDS ARROW WITH TIP RIGHTWARDS} "
    _wrapper.tabsize = 4
    _wrapper.drop_whitespace = False

    # setup the root logger
    rt = logging.getLogger()
    rt.addHandler(_LogHandler())
    rt.setLevel(logging.CRITICAL)

    # setup our logger
    _logger = logging.getLogger("yawast")
    _logger.setLevel(logging.CRITICAL)
    _logger.addHandler(_LogHandler())
    _logger.propagate = False

    # setup the logger for multiprocessing
    lg = get_logger()
    lg.level = logging.CRITICAL
    lg.addHandler(_LogHandler())

    if not no_colors:
        init()
    else:
        _no_colors = True

    if enable_debug:
        toggle_debug()


def is_debug() -> bool:
    global _debug

    return _debug


def toggle_debug():
    global _debug, _logger, _lock

    _lock.acquire()

    _debug = not _debug

    if _debug:
        _logger.setLevel(logging.DEBUG)

        rt = logging.getLogger()
        rt.setLevel(logging.DEBUG)

        lg = get_logger()
        lg.level = logging.DEBUG
    else:
        _logger.setLevel(logging.CRITICAL)

        rt = logging.getLogger()
        rt.setLevel(logging.CRITICAL)

        lg = get_logger()
        lg.level = logging.CRITICAL

    _lock.release()


def empty():
    print("")


def norm(msg: str):
    val = str(msg)

    _print("       " + val.expandtabs(tabsize=3))


def info(msg: str):
    val = str(msg)

    _print_special(Fore.GREEN, "Info", val)


def warn(msg: str):
    val = str(msg)

    _print_special(Fore.YELLOW, "Warn", val)


def vuln(msg: str):
    val = str(msg)

    _print_special(Fore.RED, "Vuln", val)


def error(msg: str):
    val = str(msg)

    _print_special(Fore.MAGENTA, "Error", val)


def debug(msg: str):
    global _init, _debug, _logger

    if _init and _debug:
        fi = cast(FrameInfo, inspect.stack()[1])
        val = str(f"{fi.function}:{msg}")

        _logger.debug(val)


def debug_exception():
    global _init, _debug

    if _init and _debug:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        val = traceback.format_exception(exc_type, exc_value, exc_traceback)

        debug("Exception: " + "".join(val))


def print_color(color: Fore, msg: str):
    global _no_colors

    if _no_colors:
        _print(msg)
    else:
        _print(color + msg + Style.RESET_ALL)


def _internal_debug(msg: str):
    val = str(msg)

    _print_special(Fore.BLUE, "Debug", val)


def _print_special(color: str, header: str, msg: str):
    global _no_colors

    if _no_colors:
        _print("[{header}] {msg}".format(header=header, msg=msg.expandtabs(tabsize=3)))
    else:
        _print(
            color
            + Style.BRIGHT
            + "[{}] ".format(header)
            + Style.RESET_ALL
            + msg.expandtabs(tabsize=3)
        )


def _print(val):
    global _wrapper, _lock

    # we wrap this in a lock, to keep the output clean
    with _lock:
        # register the message with the reporter
        clean = utils.strip_ansi_str(val)
        if clean.startswith("[Debug]"):
            reporter.register_message(clean, "debug")
        else:
            reporter.register_message(clean, "normal")

        print(_wrapper.fill(val))


class _LogHandler(logging.StreamHandler):
    def __init__(self):
        logging.Handler.__init__(self)

        self.stream = sys.stderr

        self.setFormatter(
            logging.Formatter(
                fmt="{asctime} {name}:{process}:{threadName}:{filename}:{lineno}: {message}",
                style="{",
            )
        )

    def emit(self, record):
        try:
            msg = self.format(record)

            _internal_debug(msg)
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)

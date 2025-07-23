# Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
# This file is part of yawast-ng which is released under the MIT license.
# See the LICENSE file for full license details.

from argparse import Namespace

from yawast.scanner.session import Session


def make_test_session(url="http://numorian.com"):
    args = Namespace()
    args.proxy = None
    args.user_agent = None
    args.headless = True
    args.window_size = None
    args.incognito = False
    args.disable_images = False
    args.disable_javascript = False
    args.pass_reset_page = url
    return Session(args, url)

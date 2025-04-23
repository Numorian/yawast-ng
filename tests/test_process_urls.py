#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from tests import utils
from yawast import command_line


class TestProcessUrls:
    def test_process_urls_empty(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan"])

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        assert "YAWAST Error: You must specify at least one URL." in stderr.getvalue()

    def test_process_urls_maybe_valid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "adamcaudill.com"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        assert stderr.getvalue() == ""

    def test_process_urls_invalid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "erty://adamcaudill.com"])

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        assert "YAWAST Error: Invalid URL Specified" in stderr.getvalue()

    def test_process_urls_invalid_wss(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "wss://adamcaudill.com"])

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        assert "YAWAST Error: Invalid URL Specified" in stderr.getvalue()

    def test_process_urls_invalid_shttp(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "shttp://adamcaudill.com"])

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        assert "YAWAST Error: Invalid URL Specified" in stderr.getvalue()

    def test_process_urls_invalid_ftp(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "ftp://adamcaudill.com"])

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        assert "YAWAST Error: Invalid URL Specified" in stderr.getvalue()

    def test_process_urls_invalid_port(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "http://adamcaudill.com:99999"])

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                command_line.process_urls(urls)

        assert "YAWAST Error: Invalid URL Specified" in stderr.getvalue()

    def test_process_urls_valid_port(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "http://adamcaudill.com:9999"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        assert stderr.getvalue() == ""

    def test_process_urls_valid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "http://adamcaudill.com"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        assert stderr.getvalue() == ""

    def test_process_urls_two_valid(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(
            ["scan", "http://adamcaudill.com", "http://google.com"]
        )

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        assert stderr.getvalue() == ""

    def test_process_urls_unknown_param(self):
        parser = command_line.build_parser()
        args, urls = parser.parse_known_args(["scan", "--dfghjk"])

        with utils.capture_sys_output() as (stdout, stderr):
            command_line.process_urls(urls)

        assert "YAWAST Error: Invalid parameter" in stderr.getvalue()

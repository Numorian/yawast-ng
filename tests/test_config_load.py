from unittest.mock import mock_open, patch

import pytest

from tests import utils
from yawast import config


class TestConfigLoad:
    @patch("os.path.exists")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"user_agent": "test-agent", "max_spider_pages": 5000, "include_debug_in_output": false}',
    )
    def test_load_config_valid_file(self, mock_file, mock_exists):
        # Mock the existence of the config file
        mock_exists.return_value = True

        # Call the function
        config.load_config()

        # Assert that the user_agent was set correctly
        assert config.user_agent == "test-agent"

        # Assert that max_spider_pages was set correctly
        assert config.max_spider_pages == 5000

        # Assert that include_debug_in_output was set correctly
        assert not config.include_debug_in_output

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="invalid json")
    def test_load_config_invalid_json(self, mock_file, mock_exists):
        # Mock the existence of the config file
        mock_exists.return_value = True

        # Call the function and capture the output
        with utils.capture_sys_output() as (stdout, stderr):
            config.load_config()

        # Assert that the user_agent was not set
        assert config.user_agent is None

        # Check for the error message
        assert "Error: Invalid JSON in config file." in stdout.getvalue()

    @patch("os.path.exists")
    def test_load_config_file_not_found(self, mock_exists):
        # Mock the absence of the config file
        mock_exists.return_value = False

        # Call the function
        config.load_config()

        # Assert that the user_agent remains None
        assert config.user_agent is None

    @patch("os.path.exists")
    @patch("builtins.open", side_effect=Exception("Unexpected error"))
    def test_load_config_unexpected_error(self, mock_file, mock_exists):
        # Mock the existence of the config file
        mock_exists.return_value = True

        # Call the function and capture the output
        with utils.capture_sys_output() as (stdout, stderr):
            config.load_config()

        # Assert that the user_agent was not set
        assert config.user_agent is None

        # Check for the unexpected error message
        assert "Error: Unexpected error" in stdout.getvalue()

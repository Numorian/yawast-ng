import unittest
from unittest.mock import mock_open, patch

from tests import utils
from yawast import config


class TestLoadConfig(unittest.TestCase):
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
        self.assertEqual(config.user_agent, "test-agent")

        # Assert that max_spider_pages was set correctly
        self.assertEqual(config.max_spider_pages, 5000)

        # Assert that include_debug_in_output was set correctly
        self.assertFalse(config.include_debug_in_output)

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="invalid json")
    def test_load_config_invalid_json(self, mock_file, mock_exists):
        # Mock the existence of the config file
        mock_exists.return_value = True

        # Call the function and capture the output
        with utils.capture_sys_output() as (stdout, stderr):
            config.load_config()

        # Assert that the user_agent was not set
        self.assertIsNone(config.user_agent)

        # Check for the error message
        self.assertIn("Error: Invalid JSON in config file.", stdout.getvalue())

    @patch("os.path.exists")
    def test_load_config_file_not_found(self, mock_exists):
        # Mock the absence of the config file
        mock_exists.return_value = False

        # Call the function
        config.load_config()

        # Assert that the user_agent remains None
        self.assertIsNone(config.user_agent)

    @patch("os.path.exists")
    @patch("builtins.open", side_effect=Exception("Unexpected error"))
    def test_load_config_unexpected_error(self, mock_file, mock_exists):
        # Mock the existence of the config file
        mock_exists.return_value = True

        # Call the function and capture the output
        with utils.capture_sys_output() as (stdout, stderr):
            config.load_config()

        # Assert that the user_agent was not set
        self.assertIsNone(config.user_agent)

        # Check for the unexpected error message
        self.assertIn("Error: Unexpected error", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

# this file contains a set of configuration options for YAWAST
# these are loaded at startup from ~/.yawast-ng.json

import json
import os

user_agent = None
max_spider_pages = 10000
max_spider_threads = 10
include_debug_in_output = True
allow_interactive = True
no_json_compression = False


def reset_config():
    global user_agent, max_spider_pages, max_spider_threads, include_debug_in_output, allow_interactive, no_json_compression
    user_agent = None
    max_spider_pages = 10000
    max_spider_threads = 10
    include_debug_in_output = True
    allow_interactive = True
    no_json_compression = False


def load_config():
    """
    Load the configuration from the config file.
    """
    global user_agent, max_spider_pages, include_debug_in_output, allow_interactive, max_spider_threads, no_json_compression

    reset_config()

    # check if the config file exists
    config_path = os.path.expanduser("~/.yawast-ng.json")
    if os.path.exists(config_path):
        # load the config file
        try:
            with open(config_path, "r") as f:
                config = json.load(f)

                if "user_agent" in config:
                    user_agent = config.get("user_agent", None)

                max_spider_pages = config.get("max_spider_pages", 10000)
                max_spider_threads = config.get("max_spider_threads", 10)
                include_debug_in_output = config.get("include_debug_in_output", True)
                allow_interactive = config.get("allow_interactive", True)
                no_json_compression = config.get("no_json_compression", False)
        except json.JSONDecodeError:
            print("Error: Invalid JSON in config file.")
        except Exception as e:
            print(f"Error: {e}")

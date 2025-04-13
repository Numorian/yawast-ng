#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

# this file contains a set of configuration options for YAWAST
# these are loaded at startup from ~/.yawast-ng.json

import json
import os

user_agent = None
max_spider_pages = 10000
include_debug_in_output = True


def load_config():
    """
    Load the configuration from the config file.
    """
    global user_agent, max_spider_pages, include_debug_in_output

    # check if the config file exists
    if os.path.exists("~/.yawast-ng.json"):
        # load the config file
        try:
            with open("~/.yawast-ng.json", "r") as f:
                config = json.load(f)

                if "user_agent" in config:
                    user_agent = config.get("user_agent", None)

                max_spider_pages = config.get("max_spider_pages", 10000)
                include_debug_in_output = config.get("include_debug_in_output", True)
        except json.JSONDecodeError:
            print("Error: Invalid JSON in config file.")
        except Exception as e:
            print(f"Error: {e}")

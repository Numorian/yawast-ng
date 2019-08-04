## Contributing to YAWAST

First of all, thanks for your interest in contributing to YAWAST! This document will provide you with useful information to make it as easy as possible.

### Core Contributors

* [Adam Caudill](https://github.com/adamcaudill)
  * Project Maintainer
  * macOS & Linux Build Maintainer
* [Brandon Wilson](https://github.com/brandonlw)
  * Windows Build Maintainer

### Code Changes & Pull Requests

Here are some key points to keep in mind:

* All changes to YAWAST must be made via Pull Request, and reviewed by one of the core contributors.
* Unit tests covering as many scenarios as possible are strongly encouraged.
* Code is formatted using [Black](https://github.com/psf/black).
* Care should be taken to avoid violating the plugins abstraction layer - plugins should not directly interact with a UI of any type.

### Opening Issues

Here is a high-level guide to opening issues, to save everyone time and make the process as effective as possible.

#### Feature Requests

Any feature requests should contain as much detail as possible, including sample payloads when possible. The more detail that is added, the easier it is to add a new feature.

#### Bug Reports

If you find a bug, please do open an issue so that we can address it. Please include all of the console output, as it contains important information (feel free to redact target information). If possible, run YAWAST with the `--output` option to generate a JSON file - this file contains debug output, which can help track the issue down.

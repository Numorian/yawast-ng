---
layout: default
title: Installation
permalink: /installation/
---

### Installing

The simplest installation method on most platforms is to use the [pipx](https://pipxproject.github.io/pipx/) installer (for Windows, see below):

```
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install --python python3.12 yawast-ng
```


This allows for simple updates (`pipx upgrade yawast-ng`) and makes it easy to ensure that you are always using the latest version.

yawast-ng requires Python 3.9 or newer, and is tested on macOS and Linux.

*Note:* There are additional dependencies required for certain scanning features starting with YAWAST 0.7.0; see the "Enhanced Vulnerability Scanner" section below for details.

#### Docker

yawast-ng can be run inside a docker container.

```
docker pull adcaudill/yawast-ng && docker run --rm -it adcaudill/yawast-ng scan <url> ...
```

If you would like to capture the JSON output via the `--output=` option, you will need to use a slightly different command. The following example is for macOS, Linux, etc.; for Windows, you will need to modify the command. The following mounts the current directory to the Docker image, so that it can write the JSON file: 

```
$ docker pull adcaudill/yawast-ng && docker run -v `pwd`/:/data/output/ --rm -it adcaudill/yawast-ng scan <url> --output=./output/
```

#### Kali Rolling

To install on Kali, run:

```
sudo apt-get install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
source ~/.profile
pipx install yawast-ng
```

#### Ubuntu

Installing yawast-ng on Ubuntu (19.04) is very easy:

```
sudo apt-get install python3-pip python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
source ~/.profile
pipx install yawast-ng
```

#### macOS

The version of Python shipped with macOS is too old, so the recommended solution is to use brew to install a current version:

```
brew install python
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install yawast-ng
```

### Enhanced Vulnerability Scanner

Starting in yawast-ng version 0.7.0, there is a new vulnerability scanner that performs tests that aren't possible using Python alone. To accomplish this, the new vulnerability scanner uses Chrome via Selenium, which adds a few additional dependencies:

* Google Chrome
* ChromeDriver

Storting in version 0.12.0, when using this feature, yawast-ng will attempt to download the appropriate ChromeDriver for the version of Chrome you have installed. Prior to 0.12.0, yawast-ng required ChromeDriver to be available on the PATH.

Other browsers are not currently supported.

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
pipx install --python python3.7 yawast
```


This allows for simple updates (`pipx upgrade yawast`) and makes it easy to ensure that you are always using the latest version.

YAWAST requires Python 3.7, and is tested on Mac OSX, Linux, and Windows.

*Note:* There are additional dependencies required for certain scanning features starting with YAWAST 0.7.0; see the "Enhanced Vulnerability Scanner" section below for details.

#### Docker

YAWAST can be run inside a docker container.

```
docker pull adamcaudill/yawast && docker run --rm -it adamcaudill/yawast scan <url> ...
```

If you would like to capture the JSON output via the `--output=` option, you will need to use a slightly different command. The following example is for macOS, Linux, etc.; for Windows, you will need to modify the command. The following mounts the current directory to the Docker image, so that it can write the JSON file: 

```
$ docker pull adamcaudill/yawast && docker run -v `pwd`/:/data/output/ --rm -it adamcaudill/yawast scan <url> --output=./output/
```

#### Kali Rolling

To install on Kali, run:

```
sudo apt-get install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
source ~/.profile
pipx install yawast
```

#### Ubuntu

Installing YAWAST on Ubuntu (19.04) is very easy:

```
sudo apt-get install python3-pip python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
source ~/.profile
pipx install yawast
```

#### macOS

The version of Python shipped with macOS is too old, so the recommended solution is to use brew to install a current version:

```
brew install python
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install yawast
```

#### Windows

There are two ways to use YAWAST on Windows; the easiest is to use the compiled EXE available on the [releases](https://github.com/adamcaudill/yawast/releases) page. This allows you to avoid installing Python and dealing with dependencies.

The other option is to install Python 3.7 64-bit and use pipx via:

```
pipx install yawast
```

### Enhanced Vulnerability Scanner

Starting in YAWAST version 0.7.0, there is a new vulnerability scanner that performs tests that aren't possible using Python alone. To accomplish this, the new vulnerability scanner uses Chrome via Selenium, which adds a few additional dependencies:

* Google Chrome
* [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/)

#### macOS

ChromeDriver can be installed via `brew` using the following commands:

```
brew tap homebrew/cask
brew cask install chromedriver
```

#### Linux

ChromeDriver for Linux can be installed using the following commands; please make sure that you are using the latest stable release from the [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/) web site.

```
wget https://chromedriver.storage.googleapis.com/73.0.3683.68/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
sudo mv chromedriver /usr/bin/chromedriver
sudo chown root:root /usr/bin/chromedriver
sudo chmod +x /usr/bin/chromedriver
```

#### Windows

You can easily install ChromeDriver on Windows via a package manager such as [Chocolatey](https://chocolatey.org/docs/installation) using the following command:

```
choco install chromedriver
```

Alternatively, you can download the appropriate ChromeDriver executable and place it in a predictable directory, then update your PATH environment variable to include that directory.

#!/usr/bin/env bash

rm requirements*.txt
pipenv lock -r | grep '=' > requirements.txt
pipenv lock -r --dev | grep '=' > requirements-dev.txt

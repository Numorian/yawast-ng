#!/usr/bin/env bash

rm requirements*.txt
pipenv lock -r > requirements.txt
pipenv lock -r --dev > requirements-dev.txt

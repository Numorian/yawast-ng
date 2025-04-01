#!/usr/bin/env bash

rm requirements*.txt
pipenv requirements > requirements.txt
pipenv requirements --dev > requirements-dev.txt

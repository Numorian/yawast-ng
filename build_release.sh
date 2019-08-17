#!/usr/bin/env bash

pipenv run python setup.py sdist bdist_wheel
pipenv run twine upload dist/*
rm -rf build
rm -rf dist
rm -rf *.egg-info

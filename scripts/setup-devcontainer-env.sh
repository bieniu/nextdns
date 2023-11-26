#!/bin/bash

pip3 --disable-pip-version-check --no-cache-dir install -r requirements-dev.txt
pre-commit install

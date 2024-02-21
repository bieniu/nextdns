#!/bin/bash

pip install uv
uv pip install --upgrade setuptools wheel
uv pip --no-cache-dir install -r requirements-dev.txt
pre-commit install

#!/bin/bash

python3.11 -m pip install uv
python3.11 -m uv venv venv --seed
source venv/bin/activate
pip install uv
uv pip install -r requirements-dev.txt
pre-commit install

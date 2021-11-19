#!/bin/bash
set -e;
black --quiet $@;
isort --quiet $@;
flake8 --ignore D,F,E203,E402,W503 $@;
# pylint --errors-only $@;
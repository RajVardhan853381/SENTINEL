#!/usr/bin/env python
# main.py -- dev convenience shim so `python main.py` still works.
# The real CLI lives in sentinels.cli so the packaged `sentinels` console
# script (defined in pyproject.toml) can find it after a non-editable install
# -- a bare top-level main.py isn't included in the built wheel.
import sys
sys.path.insert(0, "src")

from sentinels.cli import main

if __name__ == "__main__":
    main()

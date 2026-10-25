#!/usr/bin/env python3
"""Cargo RUSTC_WRAPPER entry point; preserve the jobserver through exec."""
import sys
from policy import dispatch

dispatch(sys.argv[1:])

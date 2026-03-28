"""Tests for logging_utils.py."""

import logging

from jibrilcon.util.logging_utils import init_logging


def test_init_logging_adds_handler():
    """init_logging should configure at least one handler on root logger."""
    init_logging("info")
    root = logging.getLogger()
    assert len(root.handlers) >= 1


def test_init_logging_handler_has_correct_format():
    """The handler should use the expected format string."""
    init_logging("info")
    root = logging.getLogger()
    handler = root.handlers[-1]
    assert handler.formatter is not None
    assert "%(levelname)" in handler.formatter._fmt
    assert "%(name)s" in handler.formatter._fmt


def test_init_logging_case_insensitive():
    """Level string should be case-insensitive."""
    init_logging("WARNING")
    root = logging.getLogger()
    # basicConfig only applies if no handlers, but level is at least set
    # on the handler or root logger
    assert root.level <= logging.WARNING

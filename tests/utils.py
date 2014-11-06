"""Various utils."""

import os

root_path = os.path.dirname(os.path.realpath(__file__))


def t_path(filename="."):
    """Get the path of the test file inside test directory."""
    return os.path.join(root_path, filename)

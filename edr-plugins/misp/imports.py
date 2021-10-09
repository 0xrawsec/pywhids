
try:
    import pywhids
except ImportError:
    import os
    import sys

    sys.path.append(os.path.join(os.path.realpath(
        os.path.dirname(__file__)), "../.."))

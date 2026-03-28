"""
jibrilcon.__main__
================

Python module shim that lets a user execute

    python -m jibrilcon

and receive exactly the same behaviour as

    python -m jibrilcon.cli

No public symbols are re-exported here on purpose; import CLI helpers
from ``jibrilcon.cli`` directly if you need them.
"""

from jibrilcon.cli import main

if __name__ == "__main__":
    main()

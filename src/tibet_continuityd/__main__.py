"""CLI entry: `python -m tibet_continuityd`."""
import sys

from tibet_continuityd.daemon import main

if __name__ == "__main__":
    sys.exit(main())

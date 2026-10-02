"""Allow ``python -m phishing_domain_detection`` to run the full pipeline."""

import sys

from .pipeline import main

if __name__ == "__main__":
    sys.exit(main())

"""
eduroam_log_parser.parsers
==========================
Line-level parsers for the two main FreeRADIUS log formats used in eduroam
deployments:

* :mod:`.fticks`      — F-TICKS/eduroam syslog lines
* :mod:`.radius_auth` — FreeRADIUS ``Auth:`` lines (Login OK / Login incorrect)
"""

from .fticks import parse_fticks
from .radius_auth import parse_radius_auth

__all__ = ["parse_fticks", "parse_radius_auth"]

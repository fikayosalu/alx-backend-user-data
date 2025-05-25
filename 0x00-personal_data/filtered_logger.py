#!/usr/bin/env python3
""" filtered_logger """

import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscates the values of specified fields in a log message"""
    return re.sub(rf'({"|".join(fields)})=.*?{separator}',
                  lambda m: f"{m.group(1)}={redaction}{separator}", message)

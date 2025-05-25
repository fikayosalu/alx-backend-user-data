#!/usr/bin/env python3
""" filtered_logger """

import re


def filter_datum(fields, redaction, message, separator):
    """Obfuscates the values of specified fields in a log message"""
    return re.sub(rf'({"|".join(fields)})=.*?{separator}',
                  lambda m: f"{m.group(1)}={redaction}{separator}", message)

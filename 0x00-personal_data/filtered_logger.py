#!/usr/bin/env python3
""" filtered_logger """
import logging
import re
from typing import List, Optional, cast, Dict, Any
import os
import mysql.connector
from mysql.connector.connection import MySQLConnection


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscates the values of specified fields in a log message"""
    return re.sub(rf'({"|".join(fields)})=.*?{separator}',
                  lambda m: f"{m.group(1)}={redaction}{separator}", message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION: str = "***"
    FORMAT: str = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: \
            %(message)s"
    SEPARATOR: str = ";"

    def __init__(self, fields: List[str]):
        """Initializes the formatter with a list of fields to redact"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields: List[str] = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filters sensitive fields in the log record"""
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.getMessage(), self.SEPARATOR)
        return super().format(record)


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger named 'user_data' that redacts PII fields.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger: logging.Logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler: logging.StreamHandler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))

    logger.addHandler(stream_handler)
    return logger


PII_FIELDS: tuple = ("name", "email", "phone", "ssn", "password")


def get_db() -> MySQLConnection:
    """
    Connects to a MySQL database using environment variables for credentials.

    Environment Variables:
        PERSONAL_DATA_DB_USERNAME: MySQL username (default: "root")
        PERSONAL_DATA_DB_PASSWORD: MySQL password (default: "")
        PERSONAL_DATA_DB_HOST: MySQL host (default: "localhost")
        PERSONAL_DATA_DB_NAME: MySQL database name (required)

    Returns:
        MySQLConnection: A MySQL database connection object.
    """
    username: str = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password: str = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host: str = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    database: Optional[str] = os.getenv("PERSONAL_DATA_DB_NAME")

    if database is None:
        raise ValueError("Environment variable PERSONAL_DATA_DB_NAME \
                must be set.")
    database = cast(str, database)

    conn = mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=database
    )
    return cast(MySQLConnection, conn)


def main() -> None:
    """
    Connects to the database, retrieves all users,
    and logs each user row with PII fields filtered.
    """
    logger = get_logger()
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users;")
    for row in cursor.fetchall():
        # Convert the dict row to log message format: key=value; ...
        row_dict: Dict[str, Any] = cast(Dict[str, Any], row)
        message = "; ".join(f"{k}={v}" for k, v in row_dict.items()) + ";"
        logger.info(message)
    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()

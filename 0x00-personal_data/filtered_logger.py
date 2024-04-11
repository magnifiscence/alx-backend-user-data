#!/usr/bin/env python3
""" 0x00. Personal data """

from typing import List
import re
import logging
import os
import mysql.connector


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str],
                 redaction: str, message: str, separator: str) -> str:
    """Returns the log message obfuscated"""
    for field in fields:
        message = re.sub(f'{field}=.*?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the record"""
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """Returns a logging object"""
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream = logging.StreamHandler()
    stream.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(stream)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Returns a connector to a database"""
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or 'root'
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ''
    host = os.getenv('PERSONAL_DATA_DB_HOST') or 'localhost'
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    return mysql.connector.connect(
        user=user, password=passwd, host=host, database=db_name)


def main():
    """Read and filter data"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")
    logger = get_logger()
    for row in cursor:
        message = f"name={row[0]}; email={row[1]}; phone={row[2]}; " + \
                  f"ssn={row[3]}; password={row[4]}; ip={row[5]}; " + \
                  f"last_login={row[6]}; user_agent={row[7]};"
        logger.info(message)
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()

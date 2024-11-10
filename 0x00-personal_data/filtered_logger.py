#!/usr/bin/env python3
"""Regex-ing"""

import re
import logging
import os
from mysql.connector import connection
from typing import List

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


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
        """Filters values"""
        return filter_datum(
            self.fields, self.REDACTION, super(RedactingFormatter,
                                               self).format(record),
            self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """Function returns a string with fields obfuscated"""
    msg = message
    for field in fields:
        msg = re.sub(field + "=.*?" + separator, field + "=" + redaction +
                     separator, msg)
    return msg


def get_logger() -> logging.Logger:
    """Returns logger obj"""
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> connection.MySQLConnection:
    """Establishes connection to database"""
    user = os.getenv("PERSONAL_DATA_DB_USERNAME")
    passwd = os.getenv("PERSONAL_DATA_DB_PASSWORD")
    host = os.getenv("PERSONAL_DATA_DB_HOST")
    db = os.getenv("PERSONAL_DATA_DB_NAME")
    cnx = connection.MySQLConnection(
            user=user,
            password=passwd,
            host=host,
            database=db
            )
    return cnx


def main():
    """Retrieves rows in the user table"""
    db = get_db()
    cx = db.cursor()
    query = 'SELECT * FROM users;'
    cx.execute(query)
    data = cx.fetchall()
    logger = get_logger()
    for item in data:
        string = "name={}; email={}; phone={}; ssn={}; password={};"\
                "ip={}; last_login={}; user_agent={};"
        string = string.format(item[0], item[1], item[2], item[3],
                               item[4], item[5], item[6], item[7])
        logger.info(string)
    cx.close
    db.close()


if __name__ == '__main__':
    main()

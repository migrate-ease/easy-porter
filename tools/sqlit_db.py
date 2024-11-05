#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/2/10 17:57
# file: sqlit_db.py
import sqlite3

from tools.error import MyError


class MySqlite(object):

    def __init__(self, db):
        """
        Initialization operation, database connection information (path)
        param db: -> string
            The database connection path.
        """
        self.sql_connect = db
        self.conn = None
        self.cursor = None
        self.myerror = MyError()

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.sql_connect)
        except TimeoutError as e:
            self.myerror.display(self.myerror.report(e, TimeoutError.__name__, "connect", self.sql_connect))
        except ConnectionError as e:
            self.myerror.display(self.myerror.report(e, ConnectionError.__name__, "connect", self.sql_connect))
        self.cursor = self.conn.cursor()

    def close(self):
        self.cursor.close()
        self.conn.close()

    def search_one(self, sql, data=tuple()):
        result = None
        self.connect()
        try:
            if data:
                select = self.cursor.execute(sql, data)
            else:
                select = self.cursor.execute(sql)
            result = select.fetchone()
        except Exception as e:
            print(e)
        return result

    def search_all(self, sql, data=tuple()):
        result = []
        self.connect()
        try:
            if data:
                select = self.cursor.execute(sql, data)
            else:
                select = self.cursor.execute(sql)
            result = select.fetchall()
        except Exception as e:
            print(e)
        finally:
            self.close()
        return result

    def execute(self, sql, data=tuple()):
        self.connect()
        try:
            if data:
                self.cursor.execute(sql, data)
            else:
                self.cursor.execute(sql)
            self.conn.commit()
            return True
        except Exception as e:
            print(e)
            self.conn.rollback()
            return False
        finally:
            self.close()

    def execute_many(self, sql, data=tuple()):
        self.connect()
        try:
            if data:
                self.cursor.executemany(sql, data)
            else:
                self.cursor.executemany(sql)
            self.conn.commit()
            return True
        except Exception as e:
            print(e)
            self.conn.rollback()
            return False
        finally:
            self.close()

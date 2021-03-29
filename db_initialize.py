# -*- coding: utf-8 -*-
"""
Created on Thu Nov 19 15:18:08 2020

@author: Guess who
"""

import sqlite3
from sqlite3 import Error
import hashlib

def hash_encode(string):
    """
    This module used to hash input password in
    order to match encoded passwords in the database
    """
    new = hashlib.md5()
    new.update(string.encode('utf-8'))
    password_hash = new.hexdigest()
    return password_hash

def create_connection(db_file):
    """ create a database connection to a SQLite database """
    db = None
    try:
        db = sqlite3.connect(db_file)
        print(sqlite3.version)
        cursor = db.cursor()
        cursor.execute("CREATE TABLE users \
                       (username TEXT PRIMARY KEY, \
                       password TEXT)")
        cursor.execute("CREATE TABLE sessions \
                       (sessionid TEXT PRIMARY KEY, \
                       username TEXT, \
                       start_time TEXT,\
                       end_time TEXT)")
        cursor.execute("CREATE TABLE record \
                       (record_id TEXT, \
                       username TEXT, \
                       location TEXT, \
                       type TEXT, \
                       occupancy TEXT, \
                       time TEXT,\
                       flag INTEGER)")
        cursor.execute("CREATE TABLE logged_in \
                       (sessionid TEXT, \
                       username TEXT)")

        p_1 = hash_encode('password1')
        p_2 = hash_encode('password2')
        p_3 = hash_encode('password3')
        p_4 = hash_encode('password4')
        p_5 = hash_encode('password5')
        p_6 = hash_encode('password6')
        p_7 = hash_encode('password7')
        p_8 = hash_encode('password8')
        p_9 = hash_encode('password9')
        p_10 = hash_encode('password10')
        cursor.execute("INSERT INTO users \
                       VALUES \
                       ('test1','{}'),('test2','{}'),\
                       ('test3','{}'),('test4','{}'),\
                       ('test5','{}'),('test6','{}'),\
                       ('test7','{}'),('test8','{}'),\
                       ('test9','{}'),('test10','{}')".format(\
                       p_1, p_2, p_3, p_4, p_5, p_6, p_7, p_8, p_9, p_10))
        db.commit()
    except Error as e:
        print(e)
    finally:
        if db:
            db.close()


if __name__ == '__main__':
    create_connection(r"initial_database.db")

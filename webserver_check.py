import requests
import json
import re
import mariadb
import sys


def main():
    test_con_10_m14_a()
    test_con_10_m14_b()
    test_con_10_m14_d()


def test_con_10_m14_a():
    structure = get_eitsbot_data('http_sec_headers')
    scope = compliant = 0
    scope = len(structure)
    for key in structure:
        if (re.search('X-XSS-Protection: 1', key['sec_headers'])
            and (re.search('X-Frame-Options: SAMEORIGIN', key['sec_headers']))
                or re.search('X-Frame-Options: DENY', key['sec_headers'])):
            compliant += 1
    add_data("CON.10.M14.a", compliant, scope)


def test_con_10_m14_b():
    structure = get_eitsbot_data('http_sec_headers')
    scope = compliant = 0
    scope = len(structure)
    for key in structure:
        if ((re.search('Content-Security-Policy: default-src \'self\'', key['sec_headers']) or
             re.search('Content-Security-Policy: script-src \'self\'', key['sec_headers'])) and  # CSP
            # X-Content-Type-Options
            re.search('X-Content-Type-Options: nosniff', key['sec_headers']) and
            (re.search('X-Frame-Options: SAMEORIGIN', key['sec_headers']) or  # X-Frame-Options
             re.search('X-Frame-Options: DENY', key['sec_headers'])) and
            # X-XSS-Protection
            re.search('X-XSS-Protection: 1', key['sec_headers']) and
            # Strict-Transport-Security
            re.search('Strict-Transport-Security: max-age=\d+', key['sec_headers']) and
            (re.search('Cache-Control: no-store', key['sec_headers']) or    # Cache-Control
             re.search('Cache-Control: no-cache', key['sec_headers']) or
             re.search('Cache-Control: must-revalidate', key['sec_headers']) or
             re.search('Cache-Control: private', key['sec_headers']))):
            compliant += 1
    add_data("CON.10.M14.b", compliant, scope)


def test_con_10_m14_d():
    structure = get_eitsbot_data('http_sec_headers')
    scope = compliant = 0
    scope = len(structure)
    for key in structure:
        if (re.search('Set-Cookie: .*; Secure', key['sec_headers']) and
            re.search('Set-Cookie: .*; HttpOnly', key['sec_headers']) and
                re.search('Set-Cookie: .*; SameSite', key['sec_headers'])):
            compliant += 1
    add_data("CON.10.M14.d", compliant, scope)


def add_data(measure_id, compliant, scope):
    conn = db().conn
    cur = conn.cursor()
    coverage = compliant / scope
    try:
        cur.execute("UPDATE score SET scope = ?, compliant = ?, coverage = ? WHERE id = ?",
                    (scope, compliant, coverage, measure_id))
    except mariadb.Error as e:
        print(f"Error adding data to MariaDB: {e}")
    conn.commit()


def get_eitsbot_data(eitsbot_type):
    try:
        print("Calling E-ITS bot API...")
        structure = requests.get(
            'http://127.0.0.1:5000/cmdb/relation/eitsbot/' + eitsbot_type)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    print("E-ITS bot API called successfully")
    return structure.json()


class database:
    def __init__(self):
        try:
            self.conn = mariadb.connect(
                user="root",
                password="root",
                host="localhost",
                port=3306,
                database="eits"

            )
        except mariadb.Error as e:
            print(f"Error connecting to MariaDB Platform: {e}")
            sys.exit(1)
        self.cur = self.conn.cursor()


def db():
    return database()


if __name__ == "__main__":
    main()

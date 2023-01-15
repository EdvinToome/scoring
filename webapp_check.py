import requests
import json
import re
import mariadb
import sys


def main():
    test_app_3_2_m18_b()


def test_app_3_2_m18_b():
    scope = compliant = 0
    structure = get_eitsbot_data('wp_enum')
    scope = len(structure)
    for key in structure:
        if (re.search('wordfence', key['plugins'])):
            compliant += 1
    add_data("APP.3.2.M18.b", compliant, scope)


def test_app_3_2_m12_a():
    scope = compliant = 0
    structure = get_eitsbot_data('http_check')
    scope = len(structure)
    for key in structure:
        if (re.search('\d.\d', key['http-server-header']) or re.search('Debian', key['http_header']) or re.search('Ubuntu', key['http_header'])):
            continue
        else:
            compliant += 1
    add_data("APP.3.2.M12.a", compliant, scope)


def test_app_3_1_m21_d():
    scope = compliant = 0
    structure = get_eitsbot_data('http_sec_headers')
    scope = len(structure)
    for key in structure:
        if (re.search('Cookies are secured with Secure Flag in HTTPS Connection', key['sec_headers'])):
            compliant += 1
    add_data("APP.3.1.M21.d", compliant, scope)


def test_app_3_1_m20_a():
    scope = compliant = 0
    structure = get_eitsbot_data('http_check')
    scope = len(structure)
    for key in structure:
        if (key['waf'] == True):
            compliant += 1
    add_data("APP.3.1.M20.a", compliant, scope)


def test_app_3_2_m11_b():
    scope = compliant = 0
    structure = get_eitsbot_data('http_sec_headers')
    scope = len(structure)
    for key in structure:
        if (re.search('Strict_Transport_Security: Strict-Transport-Security', key['sec_headers'])):
            compliant += 1
    add_data("APP.3.2.M11.b", compliant, scope)


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

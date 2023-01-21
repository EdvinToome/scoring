import requests
import json
import re
import mariadb
import sys
from flask import Flask
app = Flask(__name__)

@app.route('/eits/network_check/<measure_id>')
def get_measure(measure_id):
    measures = { 'NET.1.2.M31.a': run_net_1_2_m31_a }
    returndata = measures[measure_id]()
    json_data = []
    json_data.append( {
        'measure_id': returndata[0],
        'compliant': returndata[1],
        'scope': returndata[2],
        'coverage': returndata[3]
    })
    return json.dumps(json_data)




def test_net_1_2_m31_a():
    structure = get_eitsbot_data('ssl_check')
    scope = compliant = 0
    scope = len(structure)
    for key in structure:
        if (re.search('TLSv1.', key['ciphers']) and not
                re.search('\sB|\sC|\sD|\sE|\sF|', key['ciphers'])):  # Check cipher strength
            compliant += 1
    return add_data("NET.1.2.M31.a", compliant, scope)


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
    return measure_id, compliant, scope, coverage


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

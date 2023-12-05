#!/usr/bin/env python3

import sys
import os
import subprocess
import tempfile
import shutil
import shlex
import sqlite3
import datetime

sys.path.append(os.path.dirname(__file__) + "/../src/nssdb")
import nssdb

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes



tempdir = tempfile.mkdtemp(
    prefix=f"/run/user/{os.getuid()}/nssdb-test-",
)



def make_cert():
    # generate x509 certificate in python
    # https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    cert_file = f"{tempdir}/test.crt"
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Province"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some Locality"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Some Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "some-common-name.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())

    # Write our certificate out to disk.
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file

def fmt_val(val):
    if type(val) == bytes:
        return "0x" + val.hex()
    return repr(val)

def print_row(row):
    for key in row.keys():
        #if key == "id":
        #    # id is random. dont compare
        #    continue
        val = row[key]
        if val == None:
            continue
        """
        if type(val) == bytes:
            try:
                val = val.decode("utf8")
            except UnicodeDecodeError:
                pass
        """
        index = index_of_column.get(key)
        if index:
            print(f"{index}: {key} = {fmt_val(val)}")
        else:
            print(f"{key} = {fmt_val(val)}")



cert_file = make_cert()
cert_name = f"Some Cert {os.path.basename(cert_file)}"
cert_trust = "TC"



# build the expected nssdb

database_dir = f"{tempdir}/nssdb-expected"

if True:
    # fix: certutil: function failed: SEC_ERROR_BAD_DATABASE: security library: bad database.
    os.makedirs(database_dir)
    args = [
        "certutil",
        "-A", # add cert
        "-i", cert_file,
        "-n", cert_name,
        "-t", cert_trust,
        "-d", database_dir,
    ]
    print("$", shlex.join(args))
    subprocess.run(args)



# build the actual nssdb

database_dir = f"{tempdir}/nssdb-actual"

if False:
    nssdb.certutil(
        d=database_dir,
        A=True,
        t=cert_trust,
        n=cert_name,
        i=cert_file,
    )

if True:
    nssdb.add(
        cert_file,
        cert_name,
        cert_trust,
        # optional
        #cert_is_ascii=False,
        database_dir=database_dir,
        #database_prefix=None,
        #password_file=None,
    )



# compare the databases

cert9_conn_expected = sqlite3.connect(f"{tempdir}/nssdb-expected/cert9.db")
key4_conn_expected = sqlite3.connect(f"{tempdir}/nssdb-expected/key4.db")

cert9_conn_actual = sqlite3.connect(f"{tempdir}/nssdb-actual/cert9.db")
key4_conn_actual = sqlite3.connect(f"{tempdir}/nssdb-actual/key4.db")

# make queries return dicts
cert9_conn_expected.row_factory = sqlite3.Row
cert9_conn_actual.row_factory = sqlite3.Row
key4_conn_expected.row_factory = sqlite3.Row
key4_conn_actual.row_factory = sqlite3.Row

# nssPublic table in cert9
# nssPrivate table in key4

# CREATE INDEX ckaid ON nssPublic (a102);
ckaid_column_name = "a102"

# TODO parse from cert9.db schema
column_of_index = {
    # CREATE INDEX issuer ON nssPublic (a81);
    "issuer": "a81",
    # CREATE INDEX subject ON nssPublic (a101);
    "subject": "a101",
    # CREATE INDEX label ON nssPublic (a3);
    "label": "a3",
    # CREATE INDEX ckaid ON nssPublic (a102);
    "ckaid": "a102",
}

# invert dict
index_of_column = dict()
for index in column_of_index.keys():
    column = column_of_index[index]
    index_of_column[column] = index

print("comparing values in cert9.db")
for row_expected in cert9_conn_expected.execute("SELECT * FROM nssPublic"):
    # find the matching row in the actual database
    ckaid = row_expected[ckaid_column_name]
    row_actual = None
    if ckaid != None:
        #print(f"ckaid = {fmt_val(ckaid)}")
        row_actual = cert9_conn_actual.execute(
            f"SELECT * FROM nssPublic WHERE {ckaid_column_name} = ?",
            (ckaid,)
        ).fetchone()
    else:
        continue
        # TODO what exactly is this extra row?
        # some initial certificate generated by certutil?
        print("row_expected:")
        print_row(row_expected)
        raise NotImplementedError(f"the expected cert9.db has a row with ckaid == None")
    if row_actual == None:
        print("ckaid values in the actual cert9.db")
        for (ckaid,) in cert9_conn_actual.execute(f"SELECT {ckaid_column_name} FROM nssPublic"):
            print(f"  {fmt_val(ckaid)}")
        raise Exception(f"failed to get row_actual with ckaid=0x{ckaid.hex()}")
    found_diff = False
    for key in row_expected.keys():
        if key == "id":
            # id is random. dont compare
            continue
        val_expected = row_expected[key]
        val_actual = row_actual[key]
        if val_expected == val_actual:
            continue
        found_diff = True
        print()
        print(f"+ {key} = {fmt_val(val_expected)}")
        print(f"- {key} = {fmt_val(val_actual)}")
    if found_diff:
        print(f"FIXME: found diff in cert with ckaid {fmt_val(ckaid)}")
    else:
        print(f"ok: no diff in cert with ckaid {fmt_val(ckaid)}")

import sys
sys.exit()

# TODO
print("comparing values in key4.db")



# list certs

if True:
    args = [
        "certutil",
        "-L", # list certs
        "-d", database_dir,
    ]
    print("$", shlex.join(args))
    subprocess.run(args)



# remove tempfiles

shutil.rmtree(tempdir)

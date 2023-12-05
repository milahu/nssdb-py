import sqlite3
import os
import tempfile
import re
import base64
import sys
import random

import cryptography.x509

cert9_create_table_sql = """
CREATE TABLE nssPublic (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a12, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a8a, a8b, a90, a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a10a, a10b, a10c, a110, a111, a120, a121, a122, a123, a124, a125, a126, a127, a128, a129, a130, a131, a132, a133, a134, a160, a161, a162, a163, a164, a165, a166, a170, a180, a181, a200, a201, a202, a210, a300, a301, a302, a400, a401, a402, a403, a404, a405, a406, a480, a481, a482, a500, a501, a502, a503, a40000211, a40000212, a80000001, ace534351, ace534352, ace534353, ace534354, ace534355, ace534356, ace534357, ace534358, ace534364, ace534365, ace534366, ace534367, ace534368, ace534369, ace534373, ace534374, ace536351, ace536352, ace536353, ace536354, ace536355, ace536356, ace536357, ace536358, ace536359, ace53635a, ace53635b, ace53635c, ace53635d, ace53635e, ace53635f, ace536360, ace5363b4, ace5363b5, ad5a0db00);
CREATE INDEX issuer ON nssPublic (a81);
CREATE INDEX subject ON nssPublic (a101);
CREATE INDEX label ON nssPublic (a3);
CREATE INDEX ckaid ON nssPublic (a102);
"""

key4_create_table_sql = """
CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a12, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a8a, a8b, a90, a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a10a, a10b, a10c, a110, a111, a120, a121, a122, a123, a124, a125, a126, a127, a128, a129, a130, a131, a132, a133, a134, a160, a161, a162, a163, a164, a165, a166, a170, a180, a181, a200, a201, a202, a210, a300, a301, a302, a400, a401, a402, a403, a404, a405, a406, a480, a481, a482, a500, a501, a502, a503, a40000211, a40000212, a80000001, ace534351, ace534352, ace534353, ace534354, ace534355, ace534356, ace534357, ace534358, ace534364, ace534365, ace534366, ace534367, ace534368, ace534369, ace534373, ace534374, ace536351, ace536352, ace536353, ace536354, ace536355, ace536356, ace536357, ace536358, ace536359, ace53635a, ace53635b, ace53635c, ace53635d, ace53635e, ace53635f, ace536360, ace5363b4, ace5363b5, ad5a0db00);
CREATE TABLE metaData (id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2);
CREATE INDEX issuer ON nssPrivate (a81);
CREATE INDEX subject ON nssPrivate (a101);
CREATE INDEX label ON nssPrivate (a3);
CREATE INDEX ckaid ON nssPrivate (a102);
"""

def add(
        cert_file,
        cert_name,
        cert_trust,
        # optional
        cert_is_ascii=False,
        database_dir=None,
        database_prefix=None,
        password_file=None,
    ):
    return certutil(
        A=True,
        i=cert_file,
        n=cert_name,
        t=cert_trust,
        # optional
        a=cert_is_ascii,
        d=database_dir,
        P=database_prefix,
        f=password_file,
    )

def certutil(
        # Cert database directory.
        # default is ~/.pki/nssdb
        d=None,

        # Add a certificate to the database
        A=False,

        # Specify the nickname of the certificate to add
        n=None,

        # Set the certificate trust attributes:
        # trustargs is of the form x,y,z where x is for SSL, y is for S/MIME,
        # and z is for code signing. Use ,, for no explicit trust.
        # p      prohibited (explicitly distrusted)
        # P      trusted peer
        # c      valid CA
        # T      trusted CA to issue client certs (implies c)
        # C      trusted CA to issue server certs (implies c)
        # u      user cert
        # w      send warning
        # g      make step-up cert
        t=None,

        # Specify the password file
        f=None,

        # Cert & Key database prefix
        P=None,

        # The input certificate is encoded in ASCII (RFC1113)
        a=False,

        # Specify the certificate file (default is stdin)
        i=None,
    ):

    if d == None:
        d = os.environ.get("HOME", "") + "/.pki/nssdb"
    elif d.startswith("sql:"):
        d = d[4:]

    if not os.path.exists(d):
        print(f"creating nssdb dir: {d}")
        os.makedirs(d)

    cert9_db_path = d + "/cert9.db"
    key4_db_path = d + "/key4.db"
    # not needed
    #pkcs11_txt_path = d + "/pkcs11.txt"

    cert9_db_conn = None
    key4_db_conn = None

    cert9_db_conn = sqlite3.connect(cert9_db_path)
    key4_db_conn = sqlite3.connect(key4_db_path)

    if os.path.getsize(cert9_db_path) == 0:
        print(f"creating cert9.db: {cert9_db_path}")
        cert9_db_conn.executescript(cert9_create_table_sql)
    else:
        print(f"using cert9.db: {cert9_db_path}")

    if os.path.getsize(key4_db_path) == 0:
        print(f"creating key4.db: {key4_db_path}")
        key4_db_conn.executescript(key4_create_table_sql)
    else:
        print(f"using key4.db: {key4_db_path}")

    tempdir = f"/run/user/{os.getuid()}"
    if not os.path.exists(tempdir):
        raise ValueError(f"tempdir does not exist: {tempdir}")

    if A == True:
        # Add a certificate to the database
        assert n != None, "certutil -A: nickname is required for this command (-n)."
        assert t != None, "certutil -A: trust is required for this command (-t)."
        assert t == "TC", f"not implemented: t={repr(t)}"

        if i != None and not os.path.exists(i):
            raise Exception(f"certutil: unable to open {repr(i)} for reading.")

        if i == None:
            # read from stdin
            i = sys.stdin

        with open(i, "rb") as fp:
            cert_pem_bytes = fp.read()

        cert_body_list = re.findall(rb"-----BEGIN CERTIFICATE-----\n([a-zA-Z0-9+/=\n]+)\n-----END CERTIFICATE-----", cert_pem_bytes)
        assert len(cert_body_list) == 1, f"found {len(cert_body_list)} certificates in the input file"
        cert_body_bytes = base64.b64decode(cert_body_list[0])

        #print("cert_body_bytes len", len(cert_body_bytes))
        # 1307

        cert = cryptography.x509.load_pem_x509_certificate(cert_pem_bytes)

        def bytes_of_int(n):
            # https://stackoverflow.com/a/12859903/10440128
            return n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\0'

        # Subject Public Key Modulus
        # https://stackoverflow.com/a/62454235/10440128
        pubkey_modulus_bytes = bytes_of_int(cert.public_key().public_numbers().n)
        import hashlib
        pubkey_modulus_sha1 = hashlib.sha1(pubkey_modulus_bytes).digest()
        #print("pubkey_modulus_sha1", pubkey_modulus_sha1.hex())
        # 0a90d4a65d7a9f2a46e19f6677ec5827d1b91a09

        #print("cert_body_bytes", cert_body_bytes.hex())

        serial_number_bytes = bytes_of_int(cert.serial_number)
        #print("serial_number_bytes", serial_number_bytes.hex())

        serial_number_idx = cert_body_bytes.find(serial_number_bytes)
        #print("serial_number_idx", serial_number_idx)
        assert serial_number_idx != -1

        before_serial_number_bytes = cert_body_bytes[(serial_number_idx - 2):serial_number_idx]
        #print("before_serial_number_bytes", before_serial_number_bytes.hex())
        # 0214

        # TODO? flip cert.issuer.public_bytes() and cert.subject.public_bytes()
        # in my test case, these 2 are equal

        values = dict(
            id=random.randint(100000000, 1000000000),

            # TODO?
            a0=bytes.fromhex("00000001"),
            a1=bytes.fromhex("01"),
            a2=bytes.fromhex("00"),

            # CREATE INDEX label ON nssPublic (a3);
            # nickname of the certificate
            a3=n.encode("utf8"),

            a11=cert_body_bytes,

            # TODO?
            a80=bytes.fromhex("00000000"),

            # CREATE INDEX issuer ON nssPublic (a81);
            a81=cert.issuer.public_bytes(),

            # TODO?
            # 0x02 == version 3?
            # cert.version.value == 2
            a82=before_serial_number_bytes + serial_number_bytes,

            # CREATE INDEX subject ON nssPublic (a101);
            a101=cert.subject.public_bytes(),

            # CREATE INDEX ckaid ON nssPublic (a102);
            a102=pubkey_modulus_sha1,

            a170=bytes.fromhex("01"),
        )

        # TODO check if certificate already exists in database

        # TODO? INSERT INTO nssPublic VALUES(169958831,X'ce534353',X'01',X'00',X'a5005a',NULL,NULL,NULL,NULL,X'301b3119301706035504030c1053656c656e69756d2057697265204341',X'021421473a7679ea8585f76585d0ce967227582d5307',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,X'01',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,X'ce534352',X'ce534352',X'ce534353',X'ce534353',NULL,NULL,NULL,NULL,X'00',X'1045901d22d2a64bc629b566d384f44de35583ce',X'74105d5b0fc5767e179feeb7f6975a12',NULL);
        # certutil says "Database needs user init"
        # but chromium should be able to use the database

        print("inserting certificate")
        sql_query = f"INSERT INTO nssPublic({','.join(values.keys())}) VALUES({','.join(map(lambda _: '?', values.keys()))})"
        sql_args = tuple(values.values())
        cert9_db_conn.execute(sql_query, sql_args)

    cert9_db_conn.commit()
    cert9_db_conn.close()

    key4_db_conn.commit()
    key4_db_conn.close()

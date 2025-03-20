# -*- coding: utf-8 -*-
"""
!pip install oqs numpy pandas scikit-learn matplotlib seaborn cryptography
!pip install py pytest pytest-xdist
!apt update && apt install -y cmake ninja-build libssl-dev unzip xsltproc doxygen graphviz python3-yaml valgrind
!rm -rf liboqs  # Remove any previous failed installations
!git clone -b main https://github.com/open-quantum-safe/liboqs.git
!mkdir -p liboqs/build && cd liboqs/build && cmake -GNinja .. && ninja
!cd liboqs/build && ninja run_tests
!rm -rf liboqs-python
!git clone https://github.com/open-quantum-safe/liboqs-python.git
!cd liboqs-python && pip install .
pip install signxml
"""

import os
import time
import sys
import hashlib
from datetime import datetime, timedelta
import base64
import xml.etree.ElementTree as ET
from google.colab import drive
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from signxml import XMLSigner, XMLVerifier, methods
from lxml import etree
import matplotlib.pyplot as plt
import csv
import random
import pandas as pd
import requests

import oqs
kem_names = oqs.get_enabled_kem_mechanisms()

# Get Signatures (as you already had):
sig_names = oqs.get_enabled_sig_mechanisms()

# Or, to be more structured:
print("\nAvailable PQC Algorithms:")
for alg_type, alg_list in [("KEMs", kem_names), ("Signatures", sig_names)]:
    print(f"  {alg_type}:")
    for alg in alg_list:
        print(f"    {alg}")


# Function to generate a synthetic Aadhaar number
def generate_aadhaar():
    return str(random.randint(100000000000, 999999999999))  # 12-digit number

# Fetch 100 fake users from RandomUser API (you can change the count)
response = requests.get("https://randomuser.me/api/?results=5000&nat=in")
data = response.json()

# Extract and store user details
user_list = []
for user in data['results']:
    user_info = {
        "Aadhaar Number": generate_aadhaar(),  # Fake Aadhaar number
        "Name": f"{user['name']['first']} {user['name']['last']}",
        "DOB": user['dob']['date'][:10],
        "Email": user['email'],
        "Mobile": user['phone'],
        "Gender": user['gender'],
        "City": user['location']['city'],
        "State": user['location']['state'],
        "Country": user['location']['country'],
    }
    user_list.append(user_info)

# Convert to DataFrame
df = pd.DataFrame(user_list)

# Save to CSV
df.to_csv("fake_aadhaar_users.csv", index=False)

print("✅ Fake user data with Aadhaar numbers saved as 'fake_aadhaar_users.csv'!")



# Step 1: Generate RSA Keys & X.509 Certificate for AUA
aua_private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
aua_public_key_rsa = aua_private_key_rsa.public_key()

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Delhi"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "New Delhi"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AUA_Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "aua.company.com"),
])

certificate_rsa = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(aua_public_key_rsa)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(aua_private_key_rsa, hashes.SHA256())
)
with open("aua_certificate_rsa.pem", "wb") as f:
    f.write(certificate_rsa.public_bytes(serialization.Encoding.PEM))

with open("aua_private_key_rsa.pem", "wb") as f:
    f.write(aua_private_key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Step 2: Generate UIDAI RSA Key Pair
private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key_rsa = private_key_rsa.public_key()
private_key_rsa_size = sys.getsizeof(private_key_rsa)  # Kyber private key size
public_key_rsa_size = sys.getsizeof(public_key_rsa)  # Kyber public key size


# Step 3: Generate Timestamp (IST)  and PID Block
def generate_timestamp_rsa():
    ist_offset = timedelta(hours=5, minutes=30)
    current_ist_time = datetime.utcnow() + ist_offset
    formatted_ts = current_ist_time.strftime("%Y-%m-%dT%H:%M:%S")
    return formatted_ts

def generate_pid_rsa(formatted_ts, name, gender, dob,email,phone,dist,state, country,lang='', ms='E', mv=100, lname='', lmv=100, dobt='', age='' , co='', house='', street='', lm='', loc='', vtc='', subdist='', pc='', po='', av='', lav='', lmv_pfa=100):

    pid_data = f"""
    <Pid ts='{formatted_ts}' ver='2.0'>
        <Demo lang='{lang}'>
            <Pi name='{name}' gender='{gender}' dob='{dob}' ms='{ms}' mv='{mv}' lname='{lname}' lmv='{lmv}' dobt='{dobt}' age='{age}' phone='{phone}' email='{email}'/>
            <Pa ms='{ms}' co='{co}' house='{house}' street='{street}' lm='{lm}' loc='{loc}' vtc='{vtc}' subdist='{subdist}' dist='{dist}' state='{state}' country='{country}' pc='{pc}' po='{po}'/>
            <Pfa ms='{ms}' mv='{lmv_pfa}' av='{av}' lav='{lav}' lmv='{lmv_pfa}'/>
        </Demo>
    </Pid>
    """.strip()

    return pid_data

# Step 4: Sign Aadhaar Request
def extract_certificate_from_signature(signed_xml):
    """Extract X.509 Certificate from the <ds:X509Certificate> inside the signed XML."""
    try:
        xml_tree = etree.fromstring(signed_xml.encode())

        # Define XML namespaces
        ns = {"ds": "http://www.w3.org/2000/09/xmldsig#"}

        # Locate the <ds:X509Certificate> tag inside <ds:KeyInfo>
        x509_cert_element = xml_tree.find(".//ds:X509Certificate", namespaces=ns)

        if x509_cert_element is None:
            raise ValueError("❌ X.509 Certificate not found inside the signature!")

        # Extract and clean Base64 certificate data
        x509_cert_base64 = x509_cert_element.text.replace("\n", "").replace(" ", "")
        x509_cert_bytes = base64.b64decode(x509_cert_base64)

        # Convert to an X.509 certificate object
        return x509.load_der_x509_certificate(x509_cert_bytes)

    except Exception as e:
        print("❌ Error extracting certificate:", str(e))
        return None


def sign_xml(xml_string, private_key, certificate):
    """ Digitally sign Aadhaar authentication XML using W3C standards """

    # Parse XML
    xml_tree = etree.fromstring(xml_string)

    # Ensure certificate matches private key
    assert certificate.public_key().public_numbers() == private_key.public_key().public_numbers(), "Certificate does not match private key!"
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
    )

    start_time = time.time()
    # Sign XML
   # Sign XML and embed X.509 certificate
    signed_xml = signer.sign(
        xml_tree,
        key=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ),
        cert=certificate.public_bytes(serialization.Encoding.PEM)
    )
    signing_time = time.time() - start_time
    signature_value_element = signed_xml.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")

    if signature_value_element is not None:
        signature_value = signature_value_element.text
         # Get size in bytes
        signature_value_bytes = base64.b64decode(signature_value)
        signature_size = len(signature_value_bytes)  # Get size in bytes
    else:
        signature_size = 0


    return etree.tostring(signed_xml, encoding="utf-8").decode("utf-8"), signing_time*1000, signature_size

def verify_signed_xml(signed_xml):
    """Verify the digital signature of Aadhaar authentication XML"""
    try:
        # Parse the full XML document
        xml_tree = etree.fromstring(signed_xml.encode())

        # Load the certificate
        #x509_cert = load_certificate(cert_path)
        x509_cert = extract_certificate_from_signature(signed_xml)

        if x509_cert is None:
            raise ValueError("❌ No valid X.509 certificate found inside the signature!")
        # Verify the document (not just <Signature>)

        start_time = time.time()
        verifier = XMLVerifier().verify(
            xml_tree,
            x509_cert=x509_cert.public_bytes(serialization.Encoding.PEM)
        )
        sign_verification_time = time.time() - start_time
        print("✅ Signature verification successful!")
        return verifier, True, sign_verification_time*1000
    except Exception as e:
        print("❌ Signature verification failed!", str(e))
        return None, False, 0



# Encrypt Session Key
def encrypt_session_key_rsa(session_key, public_key_rsa):
    start_time = time.time()
    b64_key = base64.b64encode(public_key_rsa.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode("utf-8")
    key_enc_time = time.time() - start_time
    return b64_key, key_enc_time*1000

# Compute HMAC
def compute_hmac_rsa(pid_data):
    """Compute SHA-256 HMAC"""
    return base64.b64encode(hashlib.sha256(pid_data.encode()).digest()).decode("utf-8")

# Step 5: Encrypt Aadhaar Request (AES-GCM with UIDAI Rules)
def encrypt_request_rsa(pid_xml, ts):
    start_time = time.time()
    session_key = os.urandom(32)
    session_key_time = time.time() - start_time
    iv = ts[-12:].encode()  # Last 12 bytes of `ts`
    aad = ts[-16:].encode()  # Last 16 bytes of `ts`


    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(pid_xml.encode()) + encryptor.finalize()
    encrypted_pid = iv + encryptor.tag + ciphertext + ts.encode()

    encrypt_time = time.time() - start_time
    session_key_enc, key_enc_time = encrypt_session_key_rsa(session_key, public_key_rsa)

    iv_hmac = ts[-12:].encode()  # Last 12 bytes of `ts`
    aad_hmac = ts[-16:].encode()  # Last 16 bytes of `ts`

    hmac_value = compute_hmac_rsa(pid_xml)
    cipher_hmac = Cipher(algorithms.AES(session_key), modes.GCM(iv_hmac), backend=default_backend())
    encryptor_hmac = cipher_hmac.encryptor()
    encryptor_hmac.authenticate_additional_data(aad_hmac)
    encrypted_hmac = encryptor_hmac.update(hmac_value.encode()) + encryptor_hmac.finalize()
    encrypted_hmac = iv + encryptor_hmac.tag + encrypted_hmac + ts.encode()

    session_key_size = sys.getsizeof(session_key)

    return base64.b64encode(encrypted_pid).decode("utf-8"), encrypt_time*1000, session_key_enc ,base64.b64encode(encrypted_hmac).decode("utf-8") , session_key_size ,session_key_time*1000, key_enc_time


# Step 6: Create XML Authentication Request
def create_auth_xml_rsa(uid, encrypted_session_key, encrypted_request, hmac):
    start_time = time.time()
    auth = ET.Element("Auth", uid=uid, rc="Y", tid="public", ac="1234", sa="0001", ver="2.5", txn="TestTxn", lk="LicenseKey")
    uses = ET.SubElement(auth, "Uses", pi="Y", pa="N", pfa="N", bio="N", bt="", pin="N", otp="N")
    device = ET.SubElement(auth, "Device", rdsId="DeviceID", rdsVer="1.0", dpId="DP1234", dc="code", mi="info", mc="code")
    ET.SubElement(auth, "Skey", ci="20250222").text = encrypted_session_key
    ET.SubElement(auth, "Hmac").text = hmac
    ET.SubElement(auth, "Data", type="X").text = encrypted_request
    auth_xml_time = time.time() - start_time
    skey_size = sys.getsizeof(encrypted_session_key)
    print("Skey RSA Type:", type(encrypted_session_key))

    return ET.tostring(auth, encoding="utf-8", method="xml").decode("utf-8"), auth_xml_time*1000, skey_size

#auth_xml, auth_xml_time = create_auth_xml("123456789012", encrypted_session_key_b64, encrypted_request_b64, hmac_b64, signature)

# Step 7: Decrypt Aadhaar Request
def decrypt_request_rsa(encrypted_request, encrypted_hmac ,session_key):
    start_time = time.time()
    encrypted_request = base64.b64decode(encrypted_request)
    encrypted_hmac = base64.b64decode(encrypted_hmac)

    ts = encrypted_request[-19:].decode("utf-8")
    iv, tag, ciphertext = ts[-12:].encode(), encrypted_request[12:28], encrypted_request[28:-19]
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(ts[-16:].encode())
    decrypt_time = time.time() - start_time

    ts_hmac = encrypted_hmac[-19:].decode("utf-8")
    iv_hmac, tag_hmac, ciphertext_hmac = ts_hmac[-12:].encode(), encrypted_hmac[12:28], encrypted_hmac[28:-19]
    cipher_hmac = Cipher(algorithms.AES(session_key), modes.GCM(iv_hmac, tag_hmac), backend=default_backend())
    decryptor_hmac = cipher_hmac.decryptor()
    decryptor_hmac.authenticate_additional_data(ts_hmac[-16:].encode())
    decrypted_hmac = decryptor_hmac.update(ciphertext_hmac) + decryptor_hmac.finalize()


    return decryptor.update(ciphertext) + decryptor.finalize(), decrypted_hmac ,decrypt_time*1000

def validate_hmac(decrypted_request, received_hmac):
    computed_hmac = compute_hmac_rsa(decrypted_request)
    return computed_hmac == received_hmac
# Step 8: Validate Aadhaar Authentication Request
def parse_and_validate_auth_xml_rsa(auth_xml, private_key):
    hmac_status = False
    root = ET.fromstring(auth_xml)
    skey, data, hmac = root.find("Skey").text, root.find("Data").text, root.find("Hmac").text
    start_time = time.time()
    decrypted_session_key = private_key.decrypt(
        base64.b64decode(skey),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    session_key_time = time.time() - start_time

    verifier, verify_status, verify_signature_time = verify_signed_xml(auth_xml)
    decrypted_request, decrypted_hmac ,decrypt_time = decrypt_request_rsa(data, hmac ,decrypted_session_key)
    decrypted_request = decrypted_request.decode("utf-8")
    decrypted_hmac = decrypted_hmac.decode("utf-8")

    if validate_hmac(decrypted_request , decrypted_hmac):
      print("✅ HMAC Validation Successful")
      hmac_status = True
    else:
      print("❌ HMAC Validation Failed")
      hmac_status = False
    return decrypted_request, decrypt_time, session_key_time*1000, hmac_status, verify_status, verify_signature_time

#parsed_data, decrypt_time = parse_and_validate_auth_xml(auth_xml, private_key)
#print("Parsed Authentication Data:", parsed_data)
def AUA_Encryption_rsa(uid, name, gender, dob, lang='', ms='E', mv=100, lname='', lmv=100, dobt='', age='', phone='', email='', co='', house='', street='', lm='', loc='', vtc='', subdist='', dist='', state='', country='', pc='', po='', av='', lav='', lmv_pfa=100):
    start_time = time.time();
    formatted_ts = generate_timestamp_rsa()
    pid_block = generate_pid_rsa(formatted_ts, name, gender, dob, lang, ms, mv, lname, lmv, dobt, age, phone, email, co, house, street, lm, loc, vtc, subdist, dist, state, country, pc, po, av, lav, lmv_pfa)
    print(pid_block);
    #signature = sign_request_rsa(pid_block, aua_private_key_rsa)
    encrypted_request, encrypt_time, session_key ,hmac_b64 ,session_key_size, session_key_time, key_enc_time = encrypt_request_rsa(pid_block, formatted_ts)
    #hmac_b64 = compute_hmac_rsa(pid_block)
    auth_xml, auth_xml_time, skey_size = create_auth_xml_rsa(uid, session_key , encrypted_request, hmac_b64)
    signatured_auth_xml, sign_time, signature_size = sign_xml(auth_xml, aua_private_key_rsa, certificate_rsa)
    encrypted_request_size = sys.getsizeof(encrypted_request)
    auth_xml_size = sys.getsizeof(auth_xml)
    return auth_xml, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, skey_size, sign_time, signatured_auth_xml, signature_size, key_enc_time

def UIDAI_Decryption_rsa(auth_xml):
    decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time = parse_and_validate_auth_xml_rsa(auth_xml, private_key_rsa)
    print(decrypted_request)
    return decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time
auth_xml, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, skey_size, sign_time, signatured_auth_xml, signature_size, encrypt_sessionKey_time = AUA_Encryption_rsa("414944022112","Gurneesh Singh", "M", "1990-01-01")
decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time = UIDAI_Decryption_rsa(signatured_auth_xml)
print("Benchmark Results:")
#print(f"🔑 Key Generation Time: {key_gen_time:.6f} sec")
print(f"✍️ Signing Time: {sign_time:.6f} m sec")
print(f"✍️ Verfication Signature Time : {verify_signature_time: .6f} m sec")
print(f"🔐 Encryption Time: {encrypt_time:.6f} m sec")
print(f"🔐 Decryption Time: {decrypt_time:.6f} m sec")
print(f"🔑 Session Key Generation Time: {session_key_time:.6f} m sec")
print(f"🔑 Encryption Session Key Generation Time: {encrypt_sessionKey_time:.6f} m sec")
print(f"🔑 Decryption Session Key Generation Time: {decrypt_sessionKey_time:.6f} m sec")
print(f"🔑 Session Key Size: {session_key_size} bytes")
print(f"📄 XML Creation Time: {auth_xml_time:.6f} m sec")
print(f"🔑 Private Key Size: {private_key_rsa_size} bytes")
print(f"🔑 Public Key Size: {public_key_rsa_size} bytes")
print(f"🔑 Signature Size: {signature_size} bytes")
print(f"📦 Encrypted Request Size: {encrypted_request_size} bytes")
#print(f"📦 Shared Secret Size: {ss_size} bytes")
print(f"📜 Auth XML Size: {auth_xml_size} bytes")

# Step 1: Generate RSA Keys & X.509 Certificate for AUA
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
rsa_public_key = rsa_private_key.public_key()

sig_pqc = oqs.Signature("Dilithium5")
aua_public_key_pqc = sig_pqc.generate_keypair()
aua_private_key_pqc = sig_pqc.export_secret_key()

# Encode PQC Public Key in Base64 and store in Subject Alternative Name (SAN)
aua_public_key_pqc_b64 = base64.b64encode(aua_public_key_pqc).decode("utf-8")

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Delhi"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "New Delhi"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AUA_Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "aua.company.com"),
])

certificate_pqc = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(rsa_public_key)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(aua_public_key_pqc_b64)]),  # Store PQC Public Key
        critical=False,
    )
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(rsa_private_key, hashes.SHA256())
)
with open("aua_certificate_pqc.pem", "wb") as f:
    f.write(certificate_pqc.public_bytes(serialization.Encoding.PEM))

with open("aua_private_key_pqc.pem", "wb") as f:
    f.write(base64.b64encode(aua_private_key_pqc))
# Step2: UIDAI (Server) - One-time Kyber Key Generation
def UIDAI_KEM_KeyGen():
    kem = oqs.KeyEncapsulation("Kyber1024")
    pk = kem.generate_keypair()  # Public Key
    sk = kem  # Private Key (Stored securely on UIDAI)
    return pk, sk
public_key_pqc, private_key_pqc = UIDAI_KEM_KeyGen()

kem = oqs.KeyEncapsulation("Kyber1024")
ct, shared_secret = kem.encap_secret(public_key_pqc)  # Generate ciphertext & shared secret
private_key_pqc_size = sys.getsizeof(private_key_pqc)  # Kyber private key size
public_key_pqc_size = sys.getsizeof(public_key_pqc)  # Kyber public key size

# Step 3: Generate Timestamp (IST) and PID Block
def generate_timestamp_pqc():
    ist_offset = timedelta(hours=5, minutes=30)
    current_ist_time = datetime.utcnow() + ist_offset
    formatted_ts = current_ist_time.strftime("%Y-%m-%dT%H:%M:%S")
    return formatted_ts

def generate_pid_pqc(formatted_ts, name, gender, dob, email, phone, dist , state, country,lang='', ms='E', mv=100, lname='', lmv=100, dobt='', age='' , co='', house='', street='', lm='', loc='', vtc='', subdist='', pc='', po='', av='', lav='', lmv_pfa=100):

    pid_data = f"""
    <Pid ts='{formatted_ts}' ver='2.0'>
        <Demo lang='{lang}'>
            <Pi name='{name}' gender='{gender}' dob='{dob}' ms='{ms}' mv='{mv}' lname='{lname}' lmv='{lmv}' dobt='{dobt}' age='{age}' phone='{phone}' email='{email}'/>
            <Pa ms='{ms}' co='{co}' house='{house}' street='{street}' lm='{lm}' loc='{loc}' vtc='{vtc}' subdist='{subdist}' dist='{dist}' state='{state}' country='{country}' pc='{pc}' po='{po}'/>
            <Pfa ms='{ms}' mv='{lmv_pfa}' av='{av}' lav='{lav}' lmv='{lmv_pfa}'/>
        </Demo>
    </Pid>
    """.strip()

    return pid_data

# Example Usage
#transaction_id = "txn_001"

# Step 4: Sign Aadhaar Request
def extract_pqc_public_key_from_certificate(cert_path):
    """Extract the PQC public key stored inside the X.509 certificate"""
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    certificate = x509.load_pem_x509_certificate(cert_data)
    san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    # Extract Base64-encoded PQC Public Key from SAN
    pqc_public_key_b64 = san_extension.value.get_values_for_type(x509.DNSName)[0]
    pqc_public_key = base64.b64decode(pqc_public_key_b64)

    return pqc_public_key
pqc_public_key = extract_pqc_public_key_from_certificate("aua_certificate_pqc.pem")

def extract_certificate_from_signature_pqc(signed_xml):
    """Extract X.509 Certificate from the <ds:X509Certificate> inside the signed XML."""
    try:
        xml_tree = etree.fromstring(signed_xml.encode())

        # Define XML namespaces
        ns = {"ds": "http://www.w3.org/2000/09/xmldsig#"}

        # Locate the <ds:X509Certificate> tag inside <ds:KeyInfo>
        x509_cert_element = xml_tree.find(".//ds:X509Certificate", namespaces=ns)

        if x509_cert_element is None:
            raise ValueError("❌ X.509 Certificate not found inside the signature!")

        # Extract and clean Base64 certificate data
        x509_cert_base64 = x509_cert_element.text.replace("\n", "").replace(" ", "")
        x509_cert_bytes = base64.b64decode(x509_cert_base64)

        # Convert to an X.509 certificate object
        return x509.load_der_x509_certificate(x509_cert_bytes)

    except Exception as e:
        print("❌ Error extracting certificate:", str(e))
        return None
def canonicalize_xml(xml_tree):
    """Convert XML into a canonical form (C14N)"""
    return etree.tostring(xml_tree, method="c14n", exclusive=True).decode("utf-8")

def compute_sha3_256(xml_string):
    """Compute SHA3-256 hash of the XML"""
    hash_obj = hashlib.sha3_256(xml_string.encode())
    return hash_obj.digest()  # Returns binary digest

def sign_xml_pqc(xml_string, pqc_private_key, certificate):
    """Digitally sign Aadhaar authentication XML using Dilithium5"""

    # Parse XML
    xml_tree = etree.fromstring(xml_string)
    canonical_xml = canonicalize_xml(xml_tree)
    xml_bytes = canonical_xml.encode("utf-8")

    #xml_hash = compute_sha3_256(canonical_xml)

    start_time = time.time()

    # Create PQC Signature
    pqc_signature = sig_pqc.sign(xml_bytes)
    pqc_signature_b64 = base64.b64encode(pqc_signature).decode("utf-8")
    # Sign XML using W3C XML Signature (Modifying Signature Algorithm)
    signing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    signature_size = len(pqc_signature)

    x509_cert_b64 = base64.b64encode(certificate.public_bytes(serialization.Encoding.PEM)).decode("utf-8")

    # ✅ Create Signature XML Structure
    signature_element = etree.Element("SignaturePQC")

    key_info = etree.SubElement(signature_element, "KeyInfo")
    x509_data = etree.SubElement(key_info, "X509Data")
    x509_cert_element = etree.SubElement(x509_data, "X509Certificate")
    x509_cert_element.text = x509_cert_b64  # Store Certificate in XML

    signature_value = etree.SubElement(signature_element, "SignatureValue")
    signature_value.text = pqc_signature_b64  # Store Signature in XML

    # ✅ Append Signature to XML
    xml_tree.append(signature_element)

    return etree.tostring(xml_tree, encoding="utf-8").decode("utf-8"), signing_time, signature_size


def verify_signed_xml_pqc(signed_xml):
    """Verify the digital signature of Aadhaar authentication XML (PQC)"""

    try:
        # Parse XML
        xml_tree = etree.fromstring(signed_xml.encode())
        # Extract PQC Signature
        signature_element = xml_tree.find("SignaturePQC")
        if signature_element is None:
            raise ValueError("❌ No PQC signature found in XML!")

        key_info_element = signature_element.find("KeyInfo")
        if key_info_element is None:
            raise ValueError("❌ KeyInfo element not found in XML!")

        x509_data_element = key_info_element.find("X509Data")
        if x509_data_element is None:
            raise ValueError("❌ X509Data element not found in XML!")

        x509_cert_element = x509_data_element.find("X509Certificate")
        if x509_cert_element is None:
            raise ValueError("❌ X.509 Certificate not found in XML!")

        # ✅ Extract and Decode X.509 Certificate
        x509_cert_b64 = x509_cert_element.text
        x509_cert_bytes = base64.b64decode(x509_cert_b64)
        x509_certificate = x509.load_pem_x509_certificate(x509_cert_bytes)

        # ✅ Extract PQC Public Key from Certificate
        san_extension = x509_certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        pqc_public_key_b64 = san_extension.value.get_values_for_type(x509.DNSName)[0]
        pqc_public_key = base64.b64decode(pqc_public_key_b64)

        # ✅ Extract Signature from XML
        signature_value_element = signature_element.find("SignatureValue")
        pqc_signature_b64 = signature_value_element.text
        pqc_signature = base64.b64decode(pqc_signature_b64)

        # ✅ Remove Signature Before Verification
        xml_tree.remove(signature_element)
        canonical_xml = canonicalize_xml(xml_tree)
        xml_bytes = canonical_xml.encode("utf-8")

        #xml_hash = compute_sha3_256(canonical_xml)

        start_time = time.time()
        # Verify the PQC Signature
        sig = oqs.Signature("Dilithium5")
        verification_status = sig.verify(xml_bytes, pqc_signature, pqc_public_key)

        sign_verification_time = (time.time() - start_time) * 1000  # Convert to ms

        if verification_status:
            print("✅ PQC Signature verification successful!")
            return True, sign_verification_time
        else:
            print("❌ PQC Signature verification failed!")
            return False, sign_verification_time

    except Exception as e:
        print("❌ Error during PQC signature verification:", str(e))
        return False, 0
# Compute HMAC
def compute_hmac_pqc(pid_data):
    """Compute SHA-256 HMAC"""
    return base64.b64encode(hashlib.sha256(pid_data.encode()).digest()).decode("utf-8")


# Step 5: Encrypt Aadhaar Request (AES-GCM with UIDAI Rules)
def encrypt_session_key_pqc():
    start_time = time.time()
    kem = oqs.KeyEncapsulation("Kyber1024")
    ct, shared_secret = kem.encap_secret(public_key_pqc)
    key_enc_time = time.time() - start_time
    return ct, shared_secret, key_enc_time*1000

def encrypt_request_pqc(request_data, transaction_id, ts):
    # 1️⃣ AUA uses Kyber to encapsulate a shared secret
    ct, shared_secret, key_enc_time = encrypt_session_key_pqc()

    start_time = time.time()

    # 2️⃣ Derive AES-GCM session key for this transaction
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b"Aadhaar Secure Transaction " + transaction_id.encode(),
    ).derive(shared_secret)
    session_key_time = time.time() - start_time

    iv = ts[-12:].encode()  # Last 12 bytes of `ts`
    aad = ts[-16:].encode()  # Last 16 bytes of `ts`

    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(request_data.encode()) + encryptor.finalize()
    encrypted_pid = iv + encryptor.tag + ciphertext + ts.encode()

    encrypt_time = time.time() - start_time
    session_key_size = sys.getsizeof(session_key)

    iv_hmac = ts[-12:].encode()  # Last 12 bytes of `ts`
    aad_hmac = ts[-16:].encode()  # Last 16 bytes of `ts`

    hmac_value = compute_hmac_pqc(request_data)
    cipher_hmac = Cipher(algorithms.AES(session_key), modes.GCM(iv_hmac), backend=default_backend())
    encryptor_hmac = cipher_hmac.encryptor()
    encryptor_hmac.authenticate_additional_data(aad_hmac)
    encrypted_hmac = encryptor_hmac.update(hmac_value.encode()) + encryptor_hmac.finalize()
    encrypted_hmac = iv + encryptor_hmac.tag + encrypted_hmac + ts.encode()

    return base64.b64encode(encrypted_pid).decode("utf-8"), base64.b64encode(ct).decode("utf-8"), base64.b64encode(encrypted_hmac).decode("utf-8") ,encrypt_time*1000, session_key_size, session_key_time*1000, key_enc_time

#encrypted_request_b64, ct , encrypt_time = encrypt_request(pid_data, transaction_id, formatted_ts, public_key)


#hmac_b64 = compute_hmac(pid_data)


# Step 6: Create XML Authentication Request
def create_auth_xml_pqc(uid, ct , encrypted_request, hmac):
    start_time = time.time()
    auth = ET.Element("Auth", uid=uid, rc="Y", tid="public", ac="1234", sa="0001", ver="2.5", txn="TestTxn", lk="LicenseKey")
    uses = ET.SubElement(auth, "Uses", pi="Y", pa="N", pfa="N", bio="N", bt="y", pin="N", otp="N")
    device = ET.SubElement(auth, "Device", rdsId="DeviceID", rdsVer="1.0", dpId="DP1234", dc="code", mi="info", mc="code")
    ET.SubElement(auth, "Skey", ci="20250222").text = ct
    ET.SubElement(auth, "Hmac").text = hmac
    ET.SubElement(auth, "Data", type="X").text = encrypted_request
    auth_xml_time = time.time() - start_time
    skey_size = sys.getsizeof(ct)
    return ET.tostring(auth, encoding="utf-8", method="xml").decode("utf-8") , auth_xml_time*1000, skey_size


#auth_xml, auth_xml_time = create_auth_xml("123456789012", ct , encrypted_request_b64, hmac_b64 , signature)
# Step 7: Decrypt Aadhaar Request
def decrypt_request_pqc(encrypted_request, encrypted_hmac ,session_key):
    start_time = time.time()
    encrypted_request = base64.b64decode(encrypted_request)
    encrypted_hmac = base64.b64decode(encrypted_hmac)
    ts = encrypted_request[-19:].decode("utf-8")
    iv, tag, ciphertext = ts[-12:].encode(), encrypted_request[12:28], encrypted_request[28:-19]
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(ts[-16:].encode())
    decrypt_time = time.time() - start_time

    ts_hmac = encrypted_hmac[-19:].decode("utf-8")
    iv_hmac, tag_hmac, ciphertext_hmac = ts_hmac[-12:].encode(), encrypted_hmac[12:28], encrypted_hmac[28:-19]
    cipher_hmac = Cipher(algorithms.AES(session_key), modes.GCM(iv_hmac, tag_hmac), backend=default_backend())
    decryptor_hmac = cipher_hmac.decryptor()
    decryptor_hmac.authenticate_additional_data(ts_hmac[-16:].encode())
    decrypted_hmac = decryptor_hmac.update(ciphertext_hmac) + decryptor_hmac.finalize()

    return decryptor.update(ciphertext) + decryptor.finalize() ,decrypted_hmac, decrypt_time*1000

def validate_hmac_pqc(decrypted_request, received_hmac):
    computed_hmac = compute_hmac_pqc(decrypted_request)
    return computed_hmac == received_hmac
# Step 8: Validate Aadhaar Authentication Request
def parse_and_validate_auth_xml_pqc(auth_xml, sk, transaction_id):
    hmac_status = False
    root = ET.fromstring(auth_xml)
    skey, data, hmac = root.find("Skey").text, root.find("Data").text, root.find("Hmac").text
    # 1️⃣ UIDAI decapsulates to recover shared secret

    # 2️⃣ Derive AES-GCM session key (same as AUA)
    start_time = time.time()
    shared_secret = sk.decap_secret(base64.b64decode(skey))  # Recover shared secre
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b"Aadhaar Secure Transaction " + transaction_id.encode(),
    ).derive(shared_secret)
    session_key_time = time.time() - start_time
    verify_status, verify_signature_time = verify_signed_xml_pqc(auth_xml)


    decrypted_request, decrypted_hmac ,decrypt_time = decrypt_request_pqc(data, hmac,session_key)
    decrypted_request = decrypted_request.decode("utf-8")
    decrypted_hmac = decrypted_hmac.decode("utf-8")

    if validate_hmac_pqc(decrypted_request , decrypted_hmac):
      print("✅ HMAC Validation Successful")
      hmac_status = True
    else:
      print("❌ HMAC Validation Failed")
      hmac_status = False

    return decrypted_request, decrypt_time, session_key_time*1000,  hmac_status, verify_status, verify_signature_time

#parsed_data, decrypt_time = parse_and_validate_auth_xml(auth_xml, private_key)
#print("Parsed Authentication Data:", parsed_data)
def AUA_Encryption_pqc(uid, transaction_id ,name, gender, dob, lang='', ms='E', mv=100, lname='', lmv=100, dobt='', age='', phone='', email='', co='', house='', street='', lm='', loc='', vtc='', subdist='', dist='', state='', country='', pc='', po='', av='', lav='', lmv_pfa=100):
    start_time = time.time();
    formatted_ts = generate_timestamp_pqc()
    pid_block = generate_pid_pqc(formatted_ts, name, gender, dob, lang, ms, mv, lname, lmv, dobt, age, phone, email, co, house, street, lm, loc, vtc, subdist, dist, state, country, pc, po, av, lav, lmv_pfa)
    print(pid_block);
    encrypted_request, ct_b64, hmac_b64,encrypt_time, session_key_size, session_key_time, key_enc_time = encrypt_request_pqc(pid_block, transaction_id, formatted_ts)
    #hmac_b64 = compute_hmac_pqc(pid_block)
    auth_xml, auth_xml_time , skey_size = create_auth_xml_pqc(uid, ct_b64 , encrypted_request, hmac_b64)
    #signatured_auth_xml, sign_time = sign_xml_pqc(auth_xml, aua_private_key_pqc, certificate_pqc)
    signatured_auth_xml, signing_time, signature_size = sign_xml_pqc(auth_xml, aua_private_key_pqc, certificate_pqc)
    encrypted_request_size = sys.getsizeof(encrypted_request)
    auth_xml_size = sys.getsizeof(auth_xml)

    return auth_xml, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, skey_size, signing_time, signatured_auth_xml, signature_size, key_enc_time

def UIDAI_Decryption_pqc(auth_xml, transaction_id):
    decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time = parse_and_validate_auth_xml_pqc(auth_xml, private_key_pqc, transaction_id)
    print(decrypted_request)
    return decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time
auth_xml, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, skey_size ,sign_time, signatured_auth_xml, signature_size, encrypt_sessionKey_time = AUA_Encryption_pqc("414944022112", "txn_002", "Gurneesh Singh", "M", "1990-01-01")
decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time = UIDAI_Decryption_pqc(signatured_auth_xml, "txn_002")
print("Benchmark Results:")
#print(f"🔑 Key Generation Time: {key_gen_time:.6f} sec")
print(f"✍️ Signing Time: {sign_time:.6f} m sec")
print(f"✍️ Verfication Signature Time : {verify_signature_time: .6f} m sec")
print(f"🔐 Encryption Time: {encrypt_time:.6f} m sec")
print(f"🔐 Decryption Time: {decrypt_time:.6f} m sec")
print(f"🔑 Session Key Generation Time: {session_key_time:.6f} m sec")
print(f"🔑 Encryption Session Key Time: {encrypt_sessionKey_time:.6f} m sec")
print(f"🔑 Decryption Session Key Time: {decrypt_sessionKey_time:.6f} m sec")
print(f"🔑 Session Key Size: {session_key_size} bytes")
print(f"🔑 SKey Size: {skey_size} bytes")
print(f"📄 XML Creation Time: {auth_xml_time:.6f} m sec")
print(f"🔑 Private Key Size: {private_key_pqc_size} bytes")
print(f"🔑 Public Key Size: {public_key_pqc_size} bytes")
print(f"🔑 Signature Size: {signature_size} bytes")
print(f"📦 Encrypted Request Size: {encrypted_request_size} bytes")
#print(f"📦 Shared Secret Size: {ss_size} bytes")
print(f"📜 Auth XML Size: {auth_xml_size} bytes")

# Load user data from fake_aadhaar_users.csv
user_data = pd.read_csv("fake_aadhaar_users.csv")

# Function to generate transaction IDs
def generate_txn_id():
    return f"txn_{random.randint(1000, 9999)}"

# File names
pqc_filename = "pqc_results_Kyber1024_Dilithium5.csv"

# Column Headers
headers = [
    "Request_ID", "UID", "Transaction_ID", "Name", "Gender", "DOB", "Email", "Phone",
    "City", "State", "Country", "Auth_XML_Time", "Encrypt_Time", "Session_Key_Size",
    "Session_Key_Time", "Encrypted_Request_Size", "Auth_XML_Size", "Decrypt_Time", "Encrypt_SessionKey_Time",
    "Decrypt_SessionKey_Time", "Skey_Size", "Signing_Time", "Signature_Verification_Time","Signature_Size", "Public_Key_Size", "Private_Key_Size" ,"Hmac_Status", "Verify_Status"
]

# Open both CSV files
with open(pqc_filename, mode="w", newline="") as pqc_file:
    pqc_writer = csv.writer(pqc_file)

    # Write headers to both files
    pqc_writer.writerow(["Method"] + headers)

    # Generate encryption & decryption results for each user
    for index, row in user_data.iterrows():
        uid = str(row["Aadhaar Number"])
        txn_id = generate_txn_id()
        name = row["Name"]
        gender = row["Gender"] if "Gender" in row else random.choice(["M", "F"])
        dob = row["DOB"]
        email = row["Email"]
        phone = str(row["Mobile"])
        city = row["City"]
        state = row["State"]
        country = row["Country"]


        # PQC Encryption & Decryption
        auth_xml, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, skey_size, sign_time, signatured_auth_xml, signature_size, encrypt_sessionKey_time = AUA_Encryption_pqc(
            uid, txn_id, name, gender, dob, email, phone, city, state, country
        )
        decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time = UIDAI_Decryption_pqc(signatured_auth_xml, txn_id)
        pqc_writer.writerow(["PQC", index+1, uid, txn_id, name, gender, dob, email, phone, city, state, country, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, decrypt_time, encrypt_sessionKey_time ,decrypt_sessionKey_time, skey_size, sign_time, verify_signature_time, signature_size ,public_key_pqc_size, private_key_pqc_size, hmac_status, verify_status])

print(f"✅ PQC Data saved to {pqc_filename}")


# Load user data from fake_aadhaar_users.csv
user_data = pd.read_csv("fake_aadhaar_users.csv")

# Function to generate transaction IDs
def generate_txn_id():
    return f"txn_{random.randint(1000, 9999)}"

# File names
rsa_filename = "rsa_results.csv"

# Column Headers
headers = [
    "Request_ID", "UID", "Transaction_ID", "Name", "Gender", "DOB", "Email", "Phone",
    "City", "State", "Country", "Auth_XML_Time", "Encrypt_Time", "Session_Key_Size",
    "Session_Key_Time", "Encrypted_Request_Size", "Auth_XML_Size", "Decrypt_Time", "Encrypt_SessionKey_Time",
    "Decrypt_SessionKey_Time", "Skey_Size", "Signing_Time", "Signature_Verification_Time","Signature_Size", "Public_Key_Size", "Private_Key_Size" ,"Hmac_Status", "Verify_Status"
]

# Open both CSV files
with open(rsa_filename, mode="w", newline="") as rsa_file:
    rsa_writer = csv.writer(rsa_file)

    # Write headers to both files
    rsa_writer.writerow(["Method"] + headers)

    # Generate encryption & decryption results for each user
    for index, row in user_data.iterrows():
        uid = str(row["Aadhaar Number"])
        txn_id = generate_txn_id()
        name = row["Name"]
        gender = row["Gender"] if "Gender" in row else random.choice(["M", "F"])
        dob = row["DOB"]
        email = row["Email"]
        phone = str(row["Mobile"])
        city = row["City"]
        state = row["State"]
        country = row["Country"]

        # RSA Encryption & Decryption
        auth_xml, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, skey_size, sign_time, signatured_auth_xml, signature_size, encrypt_sessionKey_time = AUA_Encryption_rsa(
            uid, name, gender, dob, email, phone, city, state, country
        )
        decrypted_request, decrypt_time, decrypt_sessionKey_time, hmac_status, verify_status, verify_signature_time = UIDAI_Decryption_rsa(signatured_auth_xml)
        rsa_writer.writerow(["RSA", index+1, uid, txn_id, name, gender, dob, email, phone, city, state, country, auth_xml_time, encrypt_time, session_key_size, session_key_time, encrypted_request_size, auth_xml_size, decrypt_time, encrypt_sessionKey_time ,decrypt_sessionKey_time, skey_size, sign_time, verify_signature_time, signature_size,public_key_rsa_size , private_key_rsa_size,hmac_status, verify_status])


print(f"✅ RSA Data saved to {rsa_filename}")


# Load CSV files
rsa_df = pd.read_csv("rsa_results.csv")
pqc_df = pd.read_csv("pqc_results_Kyber1024_Dilithium5.csv")

# Define metrics for comparison
time_metrics = ["Encrypt_Time", "Session_Key_Time", "Decrypt_Time", "Decrypt_SessionKey_Time", "Encrypt_SessionKey_Time"]
size_metrics = ["Session_Key_Size", "Encrypted_Request_Size", "Skey_Size", "Signature_Size"]

metrics = time_metrics + size_metrics

# Compute average values
rsa_avg = rsa_df[metrics].mean()
pqc_avg = pqc_df[metrics].mean()

# Convert to DataFrame for plotting
comparison_df = pd.DataFrame({"Traditional Method": rsa_avg, "PQC Method": pqc_avg})

# Plot comparisons
fig, axes = plt.subplots(3,3 , figsize=(15, 12))  # Adjust grid for all metrics
fig.suptitle("Comparison of Traditional (RSA) vs PQC Metrics", fontsize=16)

for ax, metric in zip(axes.flat, metrics):
    comparison_df.loc[metric].plot(kind="bar", ax=ax, color=["blue", "green"])
    ax.set_title(metric.replace("_", " ").title(), fontsize=12)

    # Set y-axis label based on metric type
    if metric in time_metrics:
        ax.set_ylabel("Time (ms)")
    elif metric in size_metrics:
        ax.set_ylabel("Size (Bytes)")

    ax.set_xticklabels(["Traditional Method", "PQC Method"], rotation=0)

# Adjust layout
plt.tight_layout(rect=[0, 0.03, 1, 0.97])
plt.show()

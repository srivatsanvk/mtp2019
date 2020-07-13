from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID 
import datetime
import uuid
from time import time, process_time

print('check')
value = ec.SECP224R1()
time1 = process_time()
one_day = datetime.timedelta(1, 0, 0)
pr_key = rsa.generate_private_key(
    		public_exponent=65537,
    		key_size= 2048,
    		backend=default_backend()
			)
time2= process_time()

tt_keygen = time2-time1

pub_key = pr_key.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
x509.NameAttribute(NameOID.COMMON_NAME, u'CA certificate'),
]))
builder = builder.issuer_name(x509.Name([
x509.NameAttribute(NameOID.COMMON_NAME, u'Self signed'),
]))
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime(2020, 8, 2))
builder = builder.serial_number(int(uuid.uuid4()))
builder = builder.public_key(pub_key)
builder = builder.add_extension(
x509.BasicConstraints(ca=True, path_length=None), critical=True,
)
time3 = process_time()
cert = builder.sign(
private_key=pr_key, algorithm=hashes.SHA256(),
backend=default_backend()
)
time4 = process_time()

tt_sign = time4-time3
tt_total = time4 - time1 

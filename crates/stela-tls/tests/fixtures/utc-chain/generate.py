"""Synthetic WebPKI UTC-path fixtures; cryptography 46.0.5, no real identities."""
import datetime, hashlib, json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
out = Path(__file__).parent
keys = [ec.derive_private_key(n, ec.SECP256R1()) for n in (1, 2, 3)]
names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, n)]) for n in
         ("Stela synthetic UTC root", "Stela synthetic UTC intermediate", "localhost")]
def date(year, month, day):
    return datetime.datetime(year, month, day, tzinfo=datetime.timezone.utc)
def emit(name, serial, subject, issuer, key, signer, begin, end, ca):
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(begin).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), True))
    if not ca:
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        cert = cert.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    der = cert.sign(signer, hashes.SHA256(), ecdsa_deterministic=True).public_bytes(serialization.Encoding.DER)
    (out / (name + ".der")).write_bytes(der)
emit("root", 1, names[0], names[0], keys[0], keys[0], date(2020,1,1), date(2040,1,1), True)
emit("leaf", 2, names[2], names[1], keys[2], keys[1], date(2026,1,1), date(2026,2,1), False)
for serial, name, first, last in [(3,"early",1,10),(4,"late",20,31),(5,"cover",1,31),(6,"overlap",1,20)]:
    emit(name, serial, names[1], names[0], keys[1], keys[0], date(2026,1,first), date(2026,1,last), True)
(out / "manifest.json").write_text(json.dumps({
    "generator": "Python cryptography46.0.5 deterministic ECDSA P256 SHA256",
    "purpose": "One synthetic issuer key/subject with alternate disjoint, overlapping, or covering validity paths",
    "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*.der"))}
}, indent=2) + "\n")

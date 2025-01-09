import os
import json
import datetime
import logging
import secrets
from base64 import b64encode, b64decode
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asymmetric_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ca.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
CERTS_DIR = "certs"
KEYS_DIR = "keys"
CRL_FILE = os.path.join(CERTS_DIR, "crl.json")
KEY_SIZE = 2048
SUPPORTED_ALGORITHMS = ['RSA', 'ECC']

# Ensure directories exist with proper permissions
os.makedirs(CERTS_DIR, mode=0o700, exist_ok=True)
os.makedirs(KEYS_DIR, mode=0o700, exist_ok=True)


@dataclass
class Certificate:
    """
    Represents a digital certificate with essential fields and methods.

    Attributes:
        serial_number (int): Unique identifier for the certificate
        subject (str): Certificate subject name
        public_key_pem (str): Public key in PEM format
        issuer (str): Name of the certificate issuer
        expiration_date (str): ISO format expiration date
        signature (Optional[str]): Base64 encoded digital signature
        extensions (Dict): Additional certificate extensions
    """
    serial_number: int
    subject: str
    public_key_pem: str
    issuer: str
    expiration_date: str
    signature: Optional[str] = None
    extensions: Dict[str, Any] = None

    def to_dict(self) -> dict:
        """Convert certificate to dictionary format."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> 'Certificate':
        """Create certificate from dictionary data."""
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def save_to_file(self, filepath: str) -> None:
        """Save certificate to file with proper permissions."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
            os.chmod(filepath, 0o600)
        except Exception as e:
            logger.error(f"Failed to save certificate: {e}")
            raise

    @classmethod
    def load_from_file(cls, filepath: str) -> 'Certificate':
        """Load certificate from file with validation."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load certificate: {e}")
            raise


class CRL:
    """
    Certificate Revocation List implementation with secure storage and timestamps.
    """

    def __init__(self):
        self._revoked: Dict[int, Dict[str, Any]] = {}
        self.load_crl()

    def revoke(self, serial_number: int, reason: str = "unspecified") -> None:
        """Revoke a certificate with timestamp and reason."""
        self._revoked[serial_number] = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "reason": reason
        }
        self.save_crl()

    def is_revoked(self, serial_number: int) -> bool:
        """Check if a certificate is revoked."""
        return serial_number in self._revoked

    def get_revocation_info(self, serial_number: int) -> Optional[Dict[str, Any]]:
        """Get detailed revocation information."""
        return self._revoked.get(serial_number)

    def save_crl(self) -> None:
        """Save CRL to file securely."""
        try:
            with open(CRL_FILE, 'w') as f:
                json.dump(self._revoked, f, indent=4)
            os.chmod(CRL_FILE, 0o600)
        except Exception as e:
            logger.error(f"Failed to save CRL: {e}")
            raise

    def load_crl(self) -> None:
        """Load CRL from file with validation."""
        if os.path.exists(CRL_FILE):
            try:
                with open(CRL_FILE, 'r') as f:
                    self._revoked = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load CRL: {e}")
                raise


class CertificateAuthority:
    """
    Enhanced Certificate Authority implementation with secure key management
    and comprehensive certificate lifecycle handling.
    """

    def __init__(self, name: str, key_size: int = KEY_SIZE, algorithm: str = 'RSA'):
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm. Use one of {SUPPORTED_ALGORITHMS}")

        self.name = name
        self.key_size = key_size
        self.algorithm = algorithm
        self.root_cert_path = os.path.join(CERTS_DIR, f"{self.name}_root_cert.json")
        self.private_key_path = os.path.join(KEYS_DIR, f"{self.name}_private.pem")
        self.public_key_path = os.path.join(KEYS_DIR, f"{self.name}_public.pem")
        self.crl = CRL()

        if not os.path.exists(self.root_cert_path):
            self.generate_root_certificate()

    def generate_keys(self) -> Tuple[Any, Any]:
        """Generate cryptographic key pair based on selected algorithm."""
        try:
            if self.algorithm == 'RSA':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.key_size
                )
            else:  # ECC
                private_key = ec.generate_private_key(ec.SECP256R1())

            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise

    def save_key(self, key: Any, filepath: str, password: Optional[str] = None) -> None:
        """Save key to file with encryption for private keys."""
        try:
            if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                encryption = serialization.BestAvailableEncryption(
                    password.encode()) if password else serialization.NoEncryption()
                pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                )
            else:
                pem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

            with open(filepath, 'wb') as f:
                f.write(pem)
            os.chmod(filepath, 0o600)
        except Exception as e:
            logger.error(f"Failed to save key: {e}")
            raise

    def load_private_key(self, filepath: str, password: Optional[str] = None) -> Any:
        """Load private key with optional password protection."""
        try:
            with open(filepath, 'rb') as f:
                key_data = f.read()
            return serialization.load_pem_private_key(
                key_data,
                password=password.encode() if password else None
            )
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def generate_root_certificate(self, validity_days: int = 3650) -> None:
        """Generate self-signed root certificate."""
        logger.info("Generating root certificate...")
        try:
            private_key, public_key = self.generate_keys()
            self.save_key(private_key, self.private_key_path)
            self.save_key(public_key, self.public_key_path)

            expiration_date = (datetime.datetime.utcnow() +
                               datetime.timedelta(days=validity_days)).isoformat()

            cert = Certificate(
                serial_number=secrets.randbits(32),
                subject=self.name,
                public_key_pem=public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                issuer=self.name,
                expiration_date=expiration_date,
                extensions={
                    "basic_constraints": {
                        "ca": True,
                        "path_length": None
                    },
                    "key_usage": ["digital_signature", "key_cert_sign", "crl_sign"]
                }
            )

            cert.signature = self._sign_certificate(cert, private_key)
            cert.save_to_file(self.root_cert_path)
            logger.info(f"Root certificate generated: {self.root_cert_path}")
        except Exception as e:
            logger.error(f"Root certificate generation failed: {e}")
            raise

    def _sign_certificate(self, cert: Certificate, private_key: Any) -> str:
        """Create digital signature for certificate."""
        try:
            cert_dict = cert.to_dict()
            cert_dict.pop("signature", None)
            data = json.dumps(cert_dict, sort_keys=True).encode()

            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    data,
                    asymmetric_padding.PSS(
                        mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                        salt_length=asymmetric_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:  # ECC
                signature = private_key.sign(
                    data,
                    ec.ECDSA(hashes.SHA256())
                )

            return b64encode(signature).decode()
        except Exception as e:
            logger.error(f"Certificate signing failed: {e}")
            raise

    def verify_signature(self, cert: Certificate, public_key: Any) -> bool:
        """Verify certificate signature."""
        try:
            cert_dict = cert.to_dict()
            signature = b64decode(cert_dict.pop("signature"))
            data = json.dumps(cert_dict, sort_keys=True).encode()

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    data,
                    asymmetric_padding.PSS(
                        mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                        salt_length=asymmetric_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:  # ECC
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def issue_certificate(self, subject_name: str, validity_days: int = 365) -> Certificate:
        """Issue new certificate."""
        logger.info(f"Issuing certificate for {subject_name}")
        try:
            root_private_key = self.load_private_key(self.private_key_path)
            subject_private_key, subject_public_key = self.generate_keys()

            serial_number = secrets.randbits(32)
            expiration_date = (datetime.datetime.utcnow() +
                               datetime.timedelta(days=validity_days)).isoformat()

            cert = Certificate(
                serial_number=serial_number,
                subject=subject_name,
                public_key_pem=subject_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                issuer=self.name,
                expiration_date=expiration_date,
                extensions={
                    "basic_constraints": {
                        "ca": False
                    },
                    "key_usage": ["digital_signature", "key_encipherment"]
                }
            )

            cert.signature = self._sign_certificate(cert, root_private_key)

            # Save certificate and keys
            cert_path = os.path.join(CERTS_DIR, f"{subject_name}_cert.json")
            priv_key_path = os.path.join(KEYS_DIR, f"{subject_name}_private.pem")
            pub_key_path = os.path.join(KEYS_DIR, f"{subject_name}_public.pem")

            cert.save_to_file(cert_path)
            self.save_key(subject_private_key, priv_key_path)
            self.save_key(subject_public_key, pub_key_path)

            logger.info(f"Certificate issued for {subject_name}")
            return cert
        except Exception as e:
            logger.error(f"Certificate issuance failed: {e}")
            raise

    def validate_certificate(self, cert_path: str) -> Tuple[bool, str]:
        """Validate certificate and return status with reason."""
        try:
            cert = Certificate.load_from_file(cert_path)
            root_public_key = serialization.load_pem_public_key(
                open(self.public_key_path, 'rb').read()
            )

            # Check expiration
            if datetime.datetime.fromisoformat(cert.expiration_date) < datetime.datetime.utcnow():
                return False, "Certificate has expired"

            # Check revocation
            if self.crl.is_revoked(cert.serial_number):
                return False, "Certificate has been revoked"

            # Verify signature
            if not self.verify_signature(cert, root_public_key):
                return False, "Invalid signature"

            return True, "Certificate is valid"
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            return False, f"Validation error: {str(e)}"


# Flask server implementation
app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize CA
ca = CertificateAuthority(name="ProductionCA")


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('CA_API_KEY'):
            abort(401)
        return f(*args, **kwargs)

    return decorated


# API endpoints
@app.route('/api/certificates/issue', methods=['POST'])
@require_api_key
@limiter.limit("10 per minute")
def issue_certificate_endpoint():
    """Issue new certificate endpoint."""
    try:
        data = request.get_json()
        if not data or 'subject_name' not in data:
            return jsonify({"error": "Missing required fields"}), 400

        cert = ca.issue_certificate(
            subject_name=data['subject_name'],
            validity_days=data.get('validity_days', 365)
        )
        return jsonify({"status": "success", "certificate": cert.to_dict()})
    except Exception as e:
        logger.error(f"Certificate issuance API error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/certificates/validate/<subject_name>')
@require_api_key
def validate_certificate_endpoint(subject_name):
    """Validate certificate endpoint."""
    try:
        cert_path = os.path.join(CERTS_DIR, f"{subject_name}_cert.json")
        valid, reason = ca.validate_certificate(cert_path)
        return jsonify({
            "status": "valid" if valid else "invalid",
            "reason": reason
        })
    except Exception as e:
        logger.error(f"Certificate validation API error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/certificates/revoke', methods=['POST'])
@require_api_key
def revoke_certificate_endpoint():
    """Revoke certificate endpoint."""
    try:
        data = request.get_json()
        if not data or 'serial_number' not in data:
            return jsonify({"error": "Missing serial number"}), 400

        ca.crl.revoke(
            data['serial_number'],
            reason=data.get('reason', 'unspecified')
        )
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Certificate revocation API error: {e}")
        return jsonify({"error": str(e)}), 500


class SecureMessageExchange:
    """
    Implements secure message exchange using hybrid encryption.
    """

    @staticmethod
    def generate_session_key() -> bytes:
        """Generate secure session key."""
        return Fernet.generate_key()

    @staticmethod
    def encrypt_message(message: str, certificate_path: str) -> Dict[str, str]:
        """
        Encrypt message using hybrid encryption (asymmetric + symmetric).
        """
        try:
            # Generate session key
            session_key = SecureMessageExchange.generate_session_key()
            f = Fernet(session_key)

            # Encrypt message with session key
            encrypted_message = f.encrypt(message.encode())

            # Encrypt session key with recipient's public key
            cert = Certificate.load_from_file(certificate_path)
            public_key = serialization.load_pem_public_key(
                cert.public_key_pem.encode()
            )

            encrypted_session_key = public_key.encrypt(
                session_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return {
                "encrypted_message": b64encode(encrypted_message).decode(),
                "encrypted_session_key": b64encode(encrypted_session_key).decode()
            }
        except Exception as e:
            logger.error(f"Message encryption failed: {e}")
            raise

    @staticmethod
    def decrypt_message(
            encrypted_data: Dict[str, str],
            private_key_path: str
    ) -> str:
        """
        Decrypt message using hybrid encryption.
        """
        try:
            # Load private key and decrypt session key
            private_key = serialization.load_pem_private_key(
                open(private_key_path, 'rb').read(),
                password=None
            )

            encrypted_session_key = b64decode(encrypted_data['encrypted_session_key'])
            session_key = private_key.decrypt(
                encrypted_session_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt message with session key
            f = Fernet(session_key)
            encrypted_message = b64decode(encrypted_data['encrypted_message'])
            decrypted_message = f.decrypt(encrypted_message)

            return decrypted_message.decode()
        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            raise


def main():
    """
    Demonstration of the CA system functionality.
    """
    try:
        # Issue certificate for Alice
        alice_cert = ca.issue_certificate("Alice")
        logger.info("Alice's certificate issued successfully")

        # Issue certificate for Bob
        bob_cert = ca.issue_certificate("Bob")
        logger.info("Bob's certificate issued successfully")

        # Validate certificates
        alice_valid, alice_reason = ca.validate_certificate(
            os.path.join(CERTS_DIR, "Alice_cert.json")
        )
        logger.info(f"Alice's certificate validation: {alice_reason}")

        # Demonstrate secure message exchange
        message = "Hello Bob, this is a secure message from Alice!"

        # Alice encrypts message for Bob
        encrypted_data = SecureMessageExchange.encrypt_message(
            message,
            os.path.join(CERTS_DIR, "Bob_cert.json")
        )
        logger.info("Message encrypted successfully")

        # Bob decrypts message
        decrypted_message = SecureMessageExchange.decrypt_message(
            encrypted_data,
            os.path.join(KEYS_DIR, "Bob_private.pem")
        )
        logger.info(f"Decrypted message: {decrypted_message}")

        # Demonstrate revocation
        ca.crl.revoke(alice_cert.serial_number, "key compromise")
        logger.info("Alice's certificate revoked")

        # Validate revoked certificate
        alice_valid, alice_reason = ca.validate_certificate(
            os.path.join(CERTS_DIR, "Alice_cert.json")
        )
        logger.info(f"Alice's certificate validation after revocation: {alice_reason}")

    except Exception as e:
        logger.error(f"Demonstration failed: {e}")
        raise


if __name__ == "__main__":
    if os.getenv('FLASK_ENV') == 'production':
        app.run(ssl_context='adhoc')
    else:
        main()
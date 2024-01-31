"""
Very much a work in progress.
Somehow works :)

"""

import random
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ndef.record import Record

from .Utils import *



# Collecotr ID and private key are from googles sample app, 
# if own not provided these are used
# Collector ID is hardcoded to `20180608` for this sample app google
_COLLECTOR_ID = bytes([0x01, 0x33, 0xEE, 0x80]) 


# Private key is hardcoded for this sample app google
_LONG_TERM_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIJtF+UHZ7FlsOTZ4zL40dHiAiQoT7Ta8eUKAyRucHl9oAoGCCqGSM49\nAwEHoUQDQgAEchyXj869zfmKhRi9xP7f2AK07kEo4lE7ZlWTN14jh4YBTny+hRGR\nXcUzevV9zSSPJlPHpqqu5pEwlv1xyFvE1w==\n-----END EC PRIVATE KEY-----"



# Private key version is hardcoded to 1 for this sample app
LONG_TERM_PRIVATE_KEY_VERSION = bytes([0x00, 0x00, 0x00, 0x01])


def convert(data):
    num = []
    for i in data:
        if i < 0:
            num.append(i + 256)
        else:
            num.append(i)

    return num



class NegotiateCryptoCommand:
    session_id: bytes
    terminal_nonce: bytes
    terminal_ephemeral_private_key: ec.EllipticCurvePrivateKey
    terminal_ephemeral_public_key: ec.EllipticCurvePublicKey
    terminal_ephemeral_public_key_compressed: bytes

    mobile_device_nonce: bytes

    collector_id: bytes

    long_term_private_key: ec.EllipticCurvePrivateKey

    signed_data: bytes
    
    signature_record: Record
    collector_id_record: Record
    crypto_params_record: Record

    long_term_private_key_version: bytes

    def __init__(self, mobile_device_nonce: bytes, LONG_TERM_PRIVATE_KEY:str = _LONG_TERM_PRIVATE_KEY, COLLECTOR_ID:bytes = _COLLECTOR_ID):
        """Negotiate Crypto Command

        Args:
            mobile_device_nonce (bytes): Phone provides this
            LONG_TERM_PRIVATE_KEY (str, optional): Defaults to _LONG_TERM_PRIVATE_KEY.
            COLLECTOR_ID (bytes, optional): Defaults to _COLLECTOR_ID.
        """
        self.mobile_device_nonce = mobile_device_nonce
        self.session_id = urandom(8)
        self.terminal_nonce = urandom(32)
        self.terminal_ephemeral_private_key = (
            self.generate_terminal_ephemeral_public_private_keys()
        )
        self.terminal_ephemeral_public_key = (
            self.terminal_ephemeral_private_key.public_key()
        )
        self.terminal_ephemeral_public_key_compressed = self.get_compressed_public_key()
        self.long_term_private_key = self.load_private_key(LONG_TERM_PRIVATE_KEY)

        self.long_term_private_key_version = LONG_TERM_PRIVATE_KEY_VERSION
        self.collector_id = COLLECTOR_ID

        self.session_id_record = self.create_session_id_record()
        self.collector_id_record = self.create_collector_id_record()
        self.signature_record = self.create_signature_record()
        self.crypto_params_record = self.create_crypto_params_record()
        self.negotiate_crypto_record = self.create_negotiate_crypto_record()

    ## may work
    def generate_terminal_ephemeral_public_private_keys(self, seed_value: int = None) -> ec.EllipticCurvePrivateKey:
        
        if seed_value:
            return ec.derive_private_key(seed_value, ec.SECP256R1())
        
        seed_value = random.getrandbits(128)

        if seed_value < 0:
            seed_value = seed_value * -1
        # print(seed_value)
        return ec.derive_private_key(seed_value, ec.SECP256R1())

    ## WORKING
    def load_private_key(self, key_text: str) -> ec.EllipticCurvePrivateKey:
        key = serialization.load_pem_private_key(
            bytes(key_text, "utf-8"),
            password=None,  # No password for the private key
            backend=default_backend(),
        )
        return key

    ## WORKING
    def get_compressed_public_key(self) -> bytes:
        compressed_key = (
            self.terminal_ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
        )
        return compressed_key

    def create_collector_id_record(self):
        return Record(
            type="urn:nfc:ext:cld",
            name=None,
            data=Utils.concatenate_byte_arrays([0x04], self.collector_id),
        )

    def create_negotiate_crypto_record(self):
        return Record(
            type="urn:nfc:ext:ngr",
            name=None,
            data=Utils.concatenate_byte_arrays(
                [0x00, 0x01],
                Utils.create_ndef_message_bytes(
                    [self.session_id_record, self.crypto_params_record]
                ),
            ),
        )

    def create_session_id_record(self):
        # input("session id: " + str(list(self.session_id)))
        return Record(
            type="urn:nfc:ext:ses",
            name=None,
            data=Utils.concatenate_byte_arrays(self.session_id, [0x01, 0x01]),
        )

    def create_signature_record(self):
        return Record(type="urn:nfc:ext:sig", name=None, data=Utils.concatenate_byte_arrays([0x04], self.generate_signature()))

    def generate_signature(self):
        message = (
            self.terminal_nonce
            + self.mobile_device_nonce
            + self.collector_id
            + self.terminal_ephemeral_public_key_compressed
        )

        sig = self.long_term_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        self.signed_data = sig
        return sig

    def create_crypto_params_record(self):
        return Record(
            type="urn:nfc:ext:cpr",
            name=None,
            data=Utils.concatenate_byte_arrays(
                self.terminal_nonce,
                bytes([0x01]),
                self.terminal_ephemeral_public_key_compressed,
                self.long_term_private_key_version,
                Utils.create_ndef_message_bytes(
                    [self.signature_record, self.collector_id_record]
                ),
            )
        )

    def command_to_byte_array(self):
        try:
            ndef_msg = Utils.create_ndef_message_bytes([self.negotiate_crypto_record])
            length = len(ndef_msg)
            print(length)
            return Utils.concatenate_byte_arrays(
                [0x90, 0x53, 0x00, 0x00], bytes([length]), ndef_msg, bytes([0x00])
            )
        except Exception as e:
            raise SmartTapException(
                f"Problem turning 'negotiate secure smart tap sessions' command to byte array: {e}"
            )

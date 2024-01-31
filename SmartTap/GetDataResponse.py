import io
from secrets import token_bytes

import ndef
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    derive_private_key,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .Utils import *


class GetDataResponse:
    decrypted_payload: bytes
    decrypted_smart_tap_redemption_value: str
    status: str

    def __init__(
        self,
        response: bytes,
        mobile_device_ephemeral_public_key: bytes,
        terminal_ephemeral_private_key: ec.EllipticCurvePrivateKey,
        terminal_nonce: bytes,
        collector_id: bytes,
        terminal_ephemeral_public_key_compressed: bytes,
        signed_data: bytes,
        mobile_device_nonce: bytes,
    ):
        # print(response)
        # replace Utils.getStatus with a function that retrieves the status from the response
        self.status = Utils.get_status(response)
        payload = bytes(Utils.extract_payload(response))
        # input(payload)
        # input(self.status)
        # A successful status code should start with '9'
        if not self.status.startswith("9"):
            raise Exception("Invalid status: " + self.status)

        # Assuming service_request_record is fetched/parsed from the response properly
        # replace get_service_request_record with a function that extracts the necessary record
        service_request_record = self.get_service_request_record(payload)

        record_bundle_record = self.get_record_bundle_record(service_request_record)

        session_record = self.get_session_record(service_request_record)
        # print(list(session_record.data))

        self.decrypted_payload = self.decrypt(
            mobile_device_ephemeral_public_key,
            terminal_ephemeral_private_key,
            terminal_nonce,
            mobile_device_nonce,
            collector_id,
            terminal_ephemeral_public_key_compressed,
            signed_data,
            record_bundle_record,
        )
        # if self.status == "9001":
        #     return
        self.decrypted_smart_tap_redemption_value = self.get_decrypted_payload(
            self.decrypted_payload
        ).decode("utf-8")

    def decrypt(
        self,
        mobile_device_ephemeral_public_key: bytes,
        terminal_ephemeral_private_key: ec.EllipticCurvePrivateKey,
        terminal_nonce: bytes,
        mobile_device_nonce: bytes,
        collector_id: bytes,
        terminal_ephemeral_public_key_compressed: bytes,
        signed_data: bytes,
        record_bundle_record: Record,
    ) -> bytes:
        # Load the ephemeral public key
        public_key = Utils.get_public_key_from_bytes(mobile_device_ephemeral_public_key)

        # Generate the shared secret
        shared_secret = terminal_ephemeral_private_key.exchange(ECDH(), public_key)

        # Check the payload status (expecting uncompressed)
        status = record_bundle_record.data[0]
        if status in (2, 3):
            raise SmartTapException("Expecting uncompressed payload!")

        # Get the encrypted payload
        encrypted_payload = record_bundle_record.data[1:]

        # Generate the shared key
        shared_key = self.extract_shared_key(
            mobile_device_ephemeral_public_key,
            terminal_nonce,
            mobile_device_nonce,
            collector_id,
            terminal_ephemeral_public_key_compressed,
            signed_data,
            shared_secret,
        )

        expanded_aes_key = shared_key[:16]
        iv_bytes = encrypted_payload[:12]
        ciphertext = encrypted_payload[12 : (12 + len(encrypted_payload) - 44)]

        # AES decryption
        cipher = Cipher(
            algorithms.AES(expanded_aes_key),
            modes.CTR(iv_bytes + b"\x00\x00\x00\x00"),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()

        # Check HMAC
        hmac_key = shared_key[16:]
        self.check_hmac(encrypted_payload, hmac_key, iv_bytes, ciphertext)

        return decrypted_payload

    def extract_shared_key(
        self,
        mobile_device_ephemeral_public_key,
        terminal_nonce,
        mobile_device_nonce,
        collector_id,
        terminal_ephemeral_public_key_compressed,
        signed_data,
        shared_secret,
    ):
        info = Utils.concatenate_byte_arrays(
            terminal_nonce,
            mobile_device_nonce,
            collector_id,
            terminal_ephemeral_public_key_compressed,
            signed_data,
        )

        # Using HKDF to derive the key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,
            salt=mobile_device_ephemeral_public_key,
            info=info,
            backend=default_backend(),
        )
        shared_key = hkdf.derive(shared_secret)
        return shared_key

    def check_hmac(self, encrypted_payload, hmac_key, iv_bytes, ciphertext):
        received_hmac = encrypted_payload[-32:]
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv_bytes + ciphertext)
        derived_hmac = h.finalize()

        if not derived_hmac == received_hmac:
            raise SmartTapException("Hash is incorrect!")

    def get_decrypted_payload(self, payload: bytes):
        message: list[Record] = list(message_decoder(payload))
        # print(payload)
        for rec in message:
            # print(rec)

            if rec.type == "urn:nfc:ext:asv":
                service_ndef_records: list[Record] = list(message_decoder(rec.data))
                for service_record in service_ndef_records:
                    # print(service_record)
                    if service_record.type == "urn:nfc:ext:ly":
                        loyalty_ndef_records: list[Record] = list(
                            message_decoder(service_record.data)
                        )
                        for loyalty_record in loyalty_ndef_records:
                            # print(loyalty_record.name)
                            if loyalty_record.name == "n":
                                return loyalty_record.data

                    if service_record.type == "urn:nfc:ext:gr":
                        generic_ndef_records: list[Record] = list(
                            message_decoder(service_record.data)
                        )
                        for generic_record in generic_ndef_records:
                            # print(generic_record)
                            if generic_record.name == "n":
                                return generic_record.data

        # input("no record found")
        raise Exception("No record bundle record found!")

    def get_record_bundle_record(self, service_request_record: Record):
        service_request_record_payload_records: list[Record] = list(
            message_decoder(service_request_record.data)
        )

        for record in service_request_record_payload_records:
            if record.type == "urn:nfc:ext:reb":
                return record

        raise Exception("No record bundle record found!")

    def get_session_record(self, service_request_record: Record):
        service_request_record_payload_records: list[Record] = list(
            message_decoder(service_request_record.data)
        )

        for record in service_request_record_payload_records:
            if record.type == "urn:nfc:ext:ses":
                return record

        raise Exception("No session record found!")

    def get_service_request_record(self, payload: bytes):
        message: list[Record] = list(message_decoder(payload))

        for rec in message:
            if rec.type == "urn:nfc:ext:srs":
                return rec

        raise Exception("No service request record found!")

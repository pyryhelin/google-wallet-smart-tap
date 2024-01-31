import io

from .Utils import *
from ndef.message import message_encoder, message_decoder, Record


class GetDataCommand:
    COMMAND_PREFIX = bytes([0x90, 0x50, 0x00, 0x00])  # get data apdu command
    SERVICE_TYPE = 0x12  # Hardcoded for loyalty passes

    def __init__(
        self, session_id: bytes, collector_id_record: Record, sequence_number: int
    ):
        try:
            session_record = self.create_session_record(
                session_id, sequence_number
            )  # ndef record
            merchant_record = self.create_merchant_record(
                collector_id_record
            )  # ndef record
            service_list_record = self.create_service_list_record()  # ndef record

            self.service_request_record = self.create_service_request_record(
                session_record, merchant_record, service_list_record
            )
        except Exception as e:
            raise SmartTapException(
                f"Problem creating `get smart tap data` command: {e}"
            )

    def create_service_request_record(
        self, session_record, merchant_record, service_list_record
    ) -> Record:
        # Service request NDEF message payload encapsulation

        return Record(
            type="urn:nfc:ext:srq",
            name=None,
            data=Utils.concatenate_byte_arrays(
                [0x00, 0x01],
                Utils.create_ndef_message_bytes([session_record, merchant_record, service_list_record]),
            ),
        )



    def create_service_list_record(self) -> Record:
        service_type_rec = Record(type="urn:nfc:ext:str", name=None, data=bytes([self.SERVICE_TYPE]))
        return Record(
            type="urn:nfc:ext:slr",
            name=None,
            data=Utils.create_ndef_message_bytes([service_type_rec]),
        )

    def create_merchant_record(self, collector_id_record: Record) -> Record:
        return Record(
            type="urn:nfc:ext:mer",
            name=None,
            data=Utils.create_ndef_message_bytes([collector_id_record]),
        )

    def create_session_record(self, session_id, sequence_number) -> Record:
        return Record(
            type="urn:nfc:ext:ses",
            name=None,
            data=Utils.concatenate_byte_arrays(session_id, [sequence_number, 0x01]),
        )

    def command_to_byte_array(self):
        service_request_bytes = Utils.create_ndef_message_bytes(
            [self.service_request_record]
        )
        length = len(service_request_bytes)
        return Utils.concatenate_byte_arrays(
                self.COMMAND_PREFIX,
                bytes([length]),
                service_request_bytes,
                bytes([0x00]),
            )

from .Utils import Utils
from ndef.message import message_decoder, Record

class NegotiateCryptoResponse:
    mobile_device_ephemeral_public_key: bytes
    sequence_number: int
    status: str
    def __init__(self, response):
        
        # Extract status
        self.status = Utils.get_status(response)
        self.check_status()

        # Extract the negotiate request NDEF record
        negotiate_request_record = self.get_negotiate_request_record(bytes(Utils.extract_payload(response)))

        # Parse the NDEF message to get records
        message: list[Record] =list(message_decoder(negotiate_request_record.data))
        for rec in message:
            # Looking for 'ses' (0x73, 0x65, 0x73)
            if rec.type == 'urn:nfc:ext:ses':
                # Get the sequence number
                self.sequence_number = int(rec.data[8])
            # Looking for 'dpk' (0x64, 0x70, 0x6B)
            if rec.type == 'urn:nfc:ext:dpk':
                # Get the mobile device ephemeral public key
                self.mobile_device_ephemeral_public_key = bytes(rec.data)
    
        # raise Exception(f"Problem parsing `negotiate secure smart tap sessions` response: {e}")
        if not self.mobile_device_ephemeral_public_key:
            raise Exception("No mobile device ephemeral public key found!")
        if not self.sequence_number:
            raise Exception("No sequence number found!")
        
    def check_status(self):
        # Check if status is valid
        if self.status != "9000":
            if self.status == "9500":
                raise Exception("Unable to authenticate")
            else:
                raise Exception(f"Invalid Status: {self.status}")

    @staticmethod
    def get_negotiate_request_record(payload:bytes) -> Record:
        # Get records from the payload
        message: list[Record] = list(message_decoder(payload))

        for rec in message:
            
            print(rec.type)
            if rec.type == 'urn:nfc:ext:nrs':
                return rec

        raise Exception("No record bundle found!")

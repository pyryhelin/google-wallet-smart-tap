from .Utils import *
from ndef.record import Record
from ndef.message import  message_encoder, message_decoder
class SelectSmartTapResponse:
    minimum_version: str
    maximum_version: str
    mobile_device_nonce: bytes
    status: str
    
    def __init__(self, response: list[int]) -> None:
        self.status = Utils.get_status(response)
        if self.status != "9000":
            raise SmartTapException(f"Invalid status: {self.status}")
        
        payload = Utils.extract_payload(response)
        four_byte_payload = [0,0,payload[0],payload[1]]
        self.minimum_version = Utils.unsigned_int_to_long(four_byte_payload)
        
        byte_num = response[2:4]
        four_byte_num = [0,0,byte_num[0],byte_num[1]]
        self.maximum_version = Utils.unsigned_int_to_long(four_byte_num)
        
        records: list[Record] = list(message_decoder(bytes(response[4:-2])))
        self.mobile_device_nonce = records[0].data[1:]
        
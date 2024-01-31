"""
    Collection of methods used by the package
    
    byte types are sometimes represented as lists of ints, sometimes as bytes 
    shouldn't affect the functionality, but readability is not great
    TODO: standardize on one type -> bytes    
"""


from cryptography.hazmat.primitives.asymmetric import ec
from ndef.message import message_encoder, message_decoder
from ndef.record import Record
import os


class SmartTapException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        

class Utils:

    # @staticmethod
    # def get_ndef_message(records):
    #     ostream = io.BytesIO()
    #     message = records
    #     list(message_encoder(message, ostream))
    #     return ostream.getvalue()
    
    # @staticmethod
    # def get_external_type_ndef_record(type, payload, ID=None):

    #     return Record(type="urn:nfc:ext:"+type, name=ID, data=payload)
        
    
    
    @staticmethod
    def parse_tlv(data: list[int]) -> dict[str, list[int]]:
        """ 
        Parses a TLV encoded byte array into a dictionary of TLV types and values
        implementation based on some java code on the interwebs, will try to find it again

        Args:
            data (list[int]): _description_

        Returns:
            dict[str, list[int]]: _description_
        """
        parsed_data:dict[str, list[int]] = {}
        index = 0
        while i < len(data):
            type_hex = f"{data[index]:02X}"

            if type_hex.startswith('DF') or type_hex.startswith('BF'):
                index += 1
                type_hex += f"{data[index]:02X}"

            index += 1
            length = data[index]

            if length == 0x81:
                index += 1
                value_length = data[index]
                index += 1
            elif length == 0x82:
                index += 1
                value_length = (data[index] << 8) + data[index + 1]
                index += 2
            elif length == 0x83:
                index += 1
                value_length = (data[index] << 16) + (data[index + 1] << 8) + data[index + 2]
                index += 3
            elif length == 0x84:
                index += 1
                value_length = (data[index] << 24) + (data[index + 1] << 16) + (data[index + 2] << 8) + data[index + 3]
                index += 4
            else:
                value_length = length
                i += 1
                
                
            value = data[index:index + value_length]
            if type_hex not in parsed_data:
                parsed_data[type_hex] = []
            parsed_data[type_hex].append(value)
            index += value_length

        return parsed_data

    
    @staticmethod
    def unsigned_int_to_long(bytes: bytes) -> int:
        """
        Converts a 4 byte array to an unsigned long

        Args:
            bytes (bytes): 4 byte array

        Returns:
            int: unsigned long constructed from the 4 bytes
        """
        return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]

    @staticmethod
    def get_random_byte_array(length: int) -> bytes:
        """Generates a random byte array of the specified length

        Args:
            length (int): length of the byte array

        Returns:
            bytes: random byte array 
        """
        return os.urandom(length)

    @staticmethod
    def get_public_key_from_bytes(pub_key_bytes:bytes) -> ec.EllipticCurvePublicKey:
        """
        Converts a compressed public key to an EllipticCurvePublicKey

        Args:
            pub_key_bytes (bytes): compressed public key bytes

        Returns:
            ec.EllipticCurvePublicKey: 
        """
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_key_bytes)
        return public_key

    @staticmethod
    def concatenate_byte_arrays(*arrays) -> bytes:
        """
        Concatenates multiple byte arrays into a single byte array
        Args:
            *arrays (bytes): multiple byte arrays
        
        
        Returns:
            bytes: concatenated byte array
        """
        concatenated = []
        for array in arrays:
            concatenated.extend(list(array))
        return bytes(concatenated)

    
    @staticmethod
    def get_status(response: list[int]) -> str:
        """
        Extracts the status from the APDU response

        Args:
            response (list[int]): APDU response

        Returns:
            str: status
        """
        return  "".join([f"{byte:02X}" for byte in response[-2:]])

    @staticmethod
    def extract_payload(response: list[int]) -> list[int]:
        """
        Extracts the payload from the APDU response

        Args:
            response (list[int]): APDU response

        Returns:
            list[int]: payload with status removed
        """
        return response[:-2]


    @staticmethod
    def create_ndef_message_bytes(records: list[Record]) -> bytes:
        """
        Creates a byte array from a list of NDEF records

        Args:
            records (list[Record]): list of NDEF records

        Returns:
            bytes: byte array of the NDEF message
        """
        
                
        msg_enc_data = message_encoder(records)
        return Utils.concatenate_byte_arrays(*list(msg_enc_data))
    
    
    #dbug
    @staticmethod
    def parse_negotiate_crypto_ndef_message(message: Record) -> list[Record]:
        
        
        print(message)
        version = list(message.data[:2])
        print("version:", str(version[0])+ ":" +str(version[1]))
        msg: list[Record] = list(message_decoder(message.data[2:]))
        print("1st record:",msg[0])
        print("    session_id:",msg[0].data[:8])
        print("    sequence:",msg[0].data[8:9])
        print("    status:",msg[0].data[9:10])
        
        print("2nd record:",msg[1])
        print("    terminal_nonce:",msg[1].data[:32])
        print("    live auth byte :",msg[1].data[32:33])
        print("    terminal compressed key len:",msg[1].data[33:66])
        print("    long term key version:",msg[1].data[66:70])
        msg: list[Record] = list(message_decoder(msg[1].data[70:]))
        print("    3rd record:",msg[0])
        print("        type:",msg[0].data[0])
        print("        signature len:",len(list(msg[0].data[1:])))
        print("    4th record:",msg[1])
        print("        type:",msg[0].data[0])
        print("        collector id:",list(msg[1].data[1:]))
        
        
                 
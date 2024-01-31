"""
    Basic implementation of the Smart Tap protocol for Google Wallet.
    
    This implemnation is based on this repo which provides a java implementation:
    https://github.com/google-wallet/smart-tap-sample-app
    
    This is a work in progress and is not yet fully implemented.
    
    The flow is currently quite fragile without much error handling or reporting other than printing. 
    Results heavily depend on the provided transceive functions implementation.
    
    More info on the protocol can be found on github and from googles documentation:
    https://github.com/kormax/google-smart-tap
    https://developers.google.com/wallet/smart-tap

    
    Other files in this project include parsing of the responses and building of the commands.
    Those files not documented very well and are not intended to be used directly. Will add docstrings later.
"""

import binascii
from .SelectOSEResponse import *
from .SelectSmartTapResponse import *
from .NegotiateCryptoCommand import *
from .NegotiateCryptoResponse import *
from .GetDataCommand import *
from .GetDataResponse import *
from typing import Callable


class PrintingList:
    data = []

    def __init__(self, data: str = "", logging: bool = True):
        self.data = [data]
        self.logging = logging

    def append(self, item):
        if self.logging:
            print(item)
        self.data.append(item)


class SmartTap:
    def __init__(
        self,
        ec_private_key: str,
        collector_id: bytes,
        transceive_function: Callable[[bytes], bytes],
        release_tag_function: Callable[[], None] = None,
    ):
        """
        SmartTap class for initiating a secure connection and performing data
        excgange using NFC-reader and SmartTap enabled Google Wallet running on Android.

        Everything is handled automatically, just call perform_secure_get_flow() to start the flow.

        Args:
            ec_private_key (str): Elliptic curve private key in PEM format. Required.
            collector_id (str): Collector id from google wallet dashboard. Required.
            transceive_function (Callable[[bytes], bytes], optional): Function for sending and receiving bytes to and from the NFC-reader. Required.
            release_taf_function (Callable[[], None], optional): Function for releasing tag from the NFC-reader. Defaults to None and is optional.
        """
        self.ec_private_key = ec_private_key
        self.collector_id = collector_id # this might not work 
        self.release_tag_func: Callable[[], None] = release_tag_function
        self.transceive_func: Callable[[bytes], bytes] = transceive_function
        self.in_nfc_session = False
        self.negotiate_crypto_response = None
        self.select_ose_response = None
        self.select_smart_tap_response = None
        self.negotiate_crypto_command = None

    def perform_secure_get_flow(self) -> bool:
        """
        Performs the secure get flow using the transceive function provided in the constructor.

        returns True if the flow was successful, False otherwise.

        """
        self.in_nfc_session = True

        descriptive_text = PrintingList("Performing secure get flow...")

        self.perform_select_ose_command(descriptive_text)

        smart_tap = False
        # check if smart tap aid is in the list of applications
        smart_tap_aid = bytes.fromhex("a000000476d0000111")

        for aid in self.select_ose_response.aids:
            if aid == smart_tap_aid:
                smart_tap = True
                break

        if not smart_tap:
            descriptive_text.append("\n* Smart Tap AID not detected!\n---")
            self.stop_command(descriptive_text)
            return False

        self.perform_select_smart_tap(descriptive_text)
        self.perform_negotiate_crypto(descriptive_text)
        self.perform_get_data(descriptive_text)

        self.stop_command()

        if self.release_tag_func:
            self.release_tag_func()

        return True

    def perform_select_ose_command(self, descriptive_text: PrintingList):
        """
        This lets us know if the wallet is a smart tap wallet or not
        and other implementation specific information.

        Args:
            descriptive_text (PrintingList): Logging list
        """
        # universal vas (value added service) id = OSE.VAS.01 (hex 4f53452e5641532e3031)
        response = self.transceive_func(
            bytes.fromhex("00A404000A4F53452E5641532E303100")
        )

        self.select_ose_response = SelectOSEResponse(response)

        descriptive_text.append(
            f"\n----\nSent `select ose` command...\n\nResponse parsed:\n"
        )
        descriptive_text.append(
            f"\n* Status:\n  {self.select_ose_response.status} (ISO 7816-4)\n"
        )
        descriptive_text.append(
            f"\n* Wallet application label:\n  {self.select_ose_response.wallet_application_label}\n"
        )
        descriptive_text.append(
            f"\n* Mobile device nonce:\n  {binascii.hexlify(bytes(self.select_ose_response.mobile_device_nonce))}\n"
        )
        descriptive_text.append(
            f"\n* Mobile device ephemeral key:\n  {binascii.hexlify(bytes(self.select_ose_response.mobile_device_ephemeral_key))}\n"
        )

        for app in self.select_ose_response.applications:
            descriptive_text.append(f"\n* Application entry:\n  {app}\n")

        descriptive_text.append("\n----\n")

    def perform_select_smart_tap(self, descriptive_text: PrintingList):
        """
        Selects the smart tap application on the wallet.

        Args:
            descriptive_text (PrintingList): Logging
        """
        response = self.transceive_func(
            bytes.fromhex("00A4040009A000000476D000011100")
        )  # smart tap aid

        self.select_smart_tap_response = SelectSmartTapResponse(response)

        descriptive_text.append(
            "\n----\nSent `select smart tap 2` command...\n\nResponse parsed:\n"
        )
        descriptive_text.append(
            f"\n* Status:\n  {self.select_smart_tap_response.status} (ISO 7816-4)\n"
        )
        descriptive_text.append(
            f"\n* Minimum Version:\n  {self.select_smart_tap_response.minimum_version}\n"
        )
        descriptive_text.append(
            f"\n* Maximum Version:\n  {self.select_smart_tap_response.maximum_version}\n"
        )

        if self.select_smart_tap_response.mobile_device_nonce:
            descriptive_text.append(
                f"\n* Mobile Device Nonce:\n  {binascii.hexlify(self.select_smart_tap_response.mobile_device_nonce)}\n"
            )

        descriptive_text.append("\n----\n")

    def perform_negotiate_crypto(self, descriptive_text: PrintingList):
        self.negotiate_crypto_command = NegotiateCryptoCommand(
            self.select_smart_tap_response.mobile_device_nonce
        )
        response = self.transceive_func(
            self.negotiate_crypto_command.command_to_byte_array()
        )

        self.negotiate_crypto_response = NegotiateCryptoResponse(response)

        descriptive_text.append(
            "\n----\nSent `negotiate smart tap secure sessions` command...\n\nResponse parsed:\n"
        )
        descriptive_text.append(
            f"\n* Status:\n  {self.negotiate_crypto_response.status} (ISO 7816-4)\n"
        )
        descriptive_text.append(
            f"\n* Mobile device ephemeral public key (compressed):\n  {binascii.hexlify(self.negotiate_crypto_response.mobile_device_ephemeral_public_key)}\n"
        )

        descriptive_text.append("\n----\n")

    def perform_get_data(self, descriptive_text: PrintingList):
        get_data_command = GetDataCommand(
            self.negotiate_crypto_command.session_id,
            self.negotiate_crypto_command.collector_id_record,
            self.negotiate_crypto_response.sequence_number + 1,
        )

        response = self.transceive_func(get_data_command.command_to_byte_array())
        get_data_response = GetDataResponse(
            response,
            self.negotiate_crypto_response.mobile_device_ephemeral_public_key,
            self.negotiate_crypto_command.terminal_ephemeral_private_key,
            self.negotiate_crypto_command.terminal_nonce,
            self.negotiate_crypto_command.collector_id,
            self.negotiate_crypto_command.terminal_ephemeral_public_key_compressed,
            self.negotiate_crypto_command.signed_data,
            self.select_smart_tap_response.mobile_device_nonce,
        )

        # TODO: Handle more data response
        # if get_data_response.status == "9001":
        #     descriptive_text.append("\n* Status:\n  9001 (ISO 7816-4)\n")
        #     descriptive_text.append("\n* More data \n")
        #     self.perform_get_data(descriptive_text)

        descriptive_text.append(
            "\n----\nSent `get smart tap data` command...\n\nResponse parsed and decrypted, contents:\n"
        )
        descriptive_text.append(
            f"  {get_data_response.decrypted_smart_tap_redemption_value}\n"
        )

        descriptive_text.append("\n----\n")
        return get_data_response

    def stop_command(self):
        self.negotiate_crypto_response = None
        self.select_ose_response = None
        self.select_smart_tap_response = None
        self.negotiate_crypto_command = None
        if self.release_tag_func:
            self.release_tag_func()

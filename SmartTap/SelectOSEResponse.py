from .Utils import *

import binascii


        
class SelectOSEResponse:
    def __init__(self, response):
        self.aids: list[bytes] = []
        self.status = Utils.get_status(response)
        self.applications: list[str] = []
        self.wallet_application_label: str
        if not self.status.startswith("9"):
            if self.status == "6A82":
                raise FileNotFoundError(f"Device not found {self.status}")
            raise SmartTapException(f"Invalid status: {self.status}")

        #try:
        base_tlv = Utils.parse_tlv(Utils.extract_payload(response))
        fci_ppse_data = self._check_base_template_and_extract_properties(base_tlv)

        if not fci_ppse_data or "61" not in fci_ppse_data:
            return

        for entry in fci_ppse_data.get("61", []):
            if self._get_directory_entry(entry):
                return
       # except Exception as e:
         #  raise SmartTapException(f"Problem parsing `select ose` response: {e}")

    def _check_base_template_and_extract_properties(self, base_tlv):
        if "6F" not in base_tlv:
            raise SmartTapException("Problem parsing `select ose` response: No FCI template!")

        fci_template_content_tlv = Utils.parse_tlv(base_tlv["6F"][0])

        if "50" not in fci_template_content_tlv:
            raise SmartTapException("Problem parsing `select ose` response: No application label!")

        self.wallet_application_label = bytes(fci_template_content_tlv["50"][0]).decode("utf-8")

        if "C0" not in fci_template_content_tlv or "C1" not in fci_template_content_tlv:
            raise SmartTapException("Problem parsing `select ose` response: Missing required tags")

        transaction_detail_bitmap = fci_template_content_tlv["C1"][0]
        self.transactionMode = self._get_transaction_mode(transaction_detail_bitmap[0])

        if "C2" in fci_template_content_tlv:
            self.mobile_device_nonce = fci_template_content_tlv["C2"][0]

        if "C3" in fci_template_content_tlv:
            self.mobile_device_ephemeral_key = fci_template_content_tlv["C3"][0]

        if "A5" not in fci_template_content_tlv:
            raise SmartTapException("Problem parsing `select ose` response: No FCI proprietary template!")

        fci_proprietary_template_content_tlv = Utils.parse_tlv(fci_template_content_tlv["A5"][0])

        if "BF0C" not in fci_proprietary_template_content_tlv:
            raise SmartTapException("Problem parsing `select ose` response: No FCI PPSE data!")

        fci_ppse_data = Utils.parse_tlv(fci_proprietary_template_content_tlv["BF0C"][0])

        if "61" not in fci_ppse_data:
            raise SmartTapException("Problem parsing `select ose` response: No directory entries!")

        return fci_ppse_data

    def _get_directory_entry(self, entry):
        directory_entry_content_tlv = Utils.parse_tlv(entry)

        if "4F" not in directory_entry_content_tlv:
            raise SmartTapException("Problem parsing `select ose` response: No ADF name!")

        aid = directory_entry_content_tlv["4F"][0]
        self.aids.append(bytes(aid))

        adf_name = binascii.hexlify(bytes(aid)).decode().upper()
        directory_entry = f"\nApplication Name: {adf_name}"

        if "50" in directory_entry_content_tlv:
            label = directory_entry_content_tlv["50"][0].decode()
            directory_entry += f", Label: {label}"

        if "87" in directory_entry_content_tlv:
            bytes_num = directory_entry_content_tlv["87"][0]
            priority = int.from_bytes(bytes_num, "big")
            directory_entry += f", Priority: {priority}"

        self.applications.append(directory_entry)
        return False

    def _get_discretionary_template_info(self, directory_entry_content_tlv, aid):

        discretionary_template_content_tlv = Utils.parse_tlv(directory_entry_content_tlv["73"][0])

        if "DF6D" in discretionary_template_content_tlv:
            bytes_num = discretionary_template_content_tlv["DF6D"][0]
            application_minimum_version = int.from_bytes(bytes_num, "big")

        # Additional discretionary template parsing logic from Java code can be added here

    @staticmethod
    def _get_transaction_mode(b):
        transaction_modes = {
            204: "Payment and Pass enabled and requested",
            200: "Payment enabled and requested, Pass enabled",
            192: "Payment enabled and requested",
            140: "Payment enabled, Pass enabled and requested",
            136: "Payment enabled, Pass enabled",
            128: "Payment enabled",
            12: "Pass enabled and requested",
            8: "Pass enabled"
        }

        if b in transaction_modes:
            return transaction_modes[b]
        else:
            raise SmartTapException("Bad transaction mode.")

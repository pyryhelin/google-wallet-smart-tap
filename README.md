# Python implementation for google smart tap procotl

## installation


```
pip install bababa
```

## usage

```python
from SmartTap import SmartTap

# Private key in pem-format 
ec_private_key = "-----BEGIN EC PRIVATE KEY-----.....-----END EC PRIVATE KEY-----"
# Collector ID is hardcoded to `20180608` for this sample app google
collector_id = bytes([0x01, 0x33, 0xEE, 0x80])

# Need to provide own implementation for the following functions
transceive_function: Callable[[bytes], bytes],
release_tag_function: Callable[[], None] 

# transceive_function is used to send/receive data to/from phone using nfc-controller 
# release_tag_function releases the tag from reader


st = SmartTap(ec_private_key, collector_id, transceive_function, release_tag_function)
# starts the communication flow
st.perform_secure_get_flow()

```


## info
Package is very much WIP

The package includes private key and collector id from googles sample app. Those will be used if own are not provided on SmartTap class initialization. More info on the protocal can be found on the kormax's repo and general info can be found on google's dev docs

Info on pass generation and account setup might be added at some point


## credits
- https://github.com/google-wallet/smart-tap-sample-app
- https://github.com/kormax/google-smart-tap
- https://developers.google.com/wallet/smart-tap


## note
Smart tap is a proprietary protocol developed by google and thus usage of it without permission might not be permitted (at least in commercial environment). This implementation is based on sample application provided by google and reverese-engineering efforts by kormax. 
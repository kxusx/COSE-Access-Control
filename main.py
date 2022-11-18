import pycose
import pycose.keys

# Create a new key
key = pycose.keys.CoseKey.from_dict({
    'kty': 'EC',
    'crv': 'P-256',
    'x': 'x',
    'y': 'y',
    'd': 'd'
})

# Create a new COSE_Sign1 object
cose = pycose.CoseSign1(
    payload=b'Hello World',
    external_aad=b'External AAD',
    key=key
)

# Sign the COSE_Sign1 object
cose.sign()

# Serialize the COSE_Sign1 object
cose.serialize()

# Deserialize the COSE_Sign1 object
cose.deserialize()

# Verify the COSE_Sign1 object
cose.verify()

# Get the payload
cose.payload






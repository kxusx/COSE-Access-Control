import pycose
import pycose.keys
# module 'pycose.keys' has no attribute 'EC2'
from pycose.keys import EC2 # <--- this is the line that fails




# generate base point and private key
base_point = pycose.keys.EC2.generate_base_point('P-256')

# Create a new key
key = pycose.keys.CoseKey.from_dict({
    'kty': 'EC',
    'crv': 'P-256',
    'x': base_point.x,
    'y': base_point.y,
    'd': base_point.d
})

print(base_point)

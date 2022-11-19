## Central authority do registration of drones

import json

p = int(input('Enter a prime number: '))
g = int(input(f'Enter a number less than {p}: '))

reg = {'p':p, 'g':g}

json_object = json.dumps(reg, indent=4)

with open("reg.json", "w") as outfile:
    outfile.write(json_object)
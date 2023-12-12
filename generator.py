import io

import pandas as pd

data = """source_ip dest_ip dest_port BLOCK/ALLOW
0.0.0.0/0 10.55.163.0/24 ALL BLOCK
10.55.163.0/24 0.0.0.0/0 ALL ALLOW
0.0.0.0/0 10.55.163.141 443/tcp ALLOW
0.0.0.0/0 10.55.163.141 6443/tcp ALLOW
0.0.0.0/0 10.55.163.141 80/tcp ALLOW
"""


# Create a DataFrame using a custom parser function
def custom_parser(x):
    parts = x.split('/')
    if len(parts) == 1:
        return [parts[0], None]
    else:
        return parts


df = pd.read_csv(io.StringIO(data), delim_whitespace=True,
                 converters={'source_ip': custom_parser, 'dest_ip': custom_parser, 'dest_port': custom_parser})
df

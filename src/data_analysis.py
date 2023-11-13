from typing import List, Union
import pandas as pd


locations = [
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled"
]


DATA_ENCODING_DICTIONARY = {
    "proto": {
        "icmp": 0,
        "tcp": 1,
        "udp": 2
    },
    "service": {
        "-": 0,
        "dhcp": 1,
        "dns": 2,
        "http": 3,
        "ssh": 4,
        "ssl": 5,
        "irc": 6
    },
    "conn_state": {
        "S0": 0,
        "S1": 1,
        "S2": 2,
        "S3": 3,
        "SF": 4,
        "REJ": 5,
        "RSTO": 6,
        "RSTR": 7,
        "RSTOS0": 8,
        "RSTRH": 9,
        "SH": 10,
        "SHR": 11,
        "OTH": 12
    },
    "label": {
        "benign": 0,
        "Malicious": 1
    },
    "detailed-label": {
        "Benign": 0,
        "Attack": 1,
        "C&C": 2,
        "C&C-FileDownload": 3,
        "C&C-HeartBeat": 4,
        "C&C-HeartBeat-Attack": 5,
        "C&C-HeartBeat-FileDownload": 6,
        "C&C-Mirai": 7,
        "C&C-PartOfAHorizontalPortScan": 8,
        "C&C-Torii": 9,
        "DDoS": 10,
        "FileDownload": 11,
        "Okiru": 12,
        "Okiru-Attack": 13,
        "PartOfAHorizontalPortScan": 14,
        "PartOfAHorizontalPortScan-Attack": 15,
    },
}

DATA_CONVERSION_DICTIONARY = {
    "detailed-label":{
        "-": "Benign"
    },
    "duration":{
        "-": 99
    },
    "orig_bytes": {
        "-": 99
    },
    "resp_bytes": {
        "-": 99
    },
    "missed_bytes": {
        "-": 99
    },
    "local_orig": {
        "-": 99
    },
    "local_resp": {
        "-": 99
    },
    "orig_pkts": {
        "-": 99
    },
    "orig_ip_bytes": {
        "-": 99
    },
    "resp_pkts": {
        "-": 99
    },
    "resp_ip_bytes": {
        "-": 99
    },
}

DATA_HEADINGS_DICTIONARY = {
    'ts': 0, 
    'uid': 1, 
    'id.orig_h': 2, 
    'id.orig_p': 3, 
    'id.resp_h': 4, 
    'id.resp_p': 5, 
    'proto': 6, 
    'service': 7, 
    'duration': 8, 
    'orig_bytes': 9, 
    'resp_bytes': 10, 
    'conn_state': 11, 
    'local_orig': 12, 
    'local_resp': 13, 
    'missed_bytes': 14, 
    'history': 15, 
    'orig_pkts': 16, 
    'orig_ip_bytes': 17, 
    'resp_pkts': 18, 
    'resp_ip_bytes': 19, 
    'tunnel_parents': 20, 
    'label': 21, 
    'detailed-label': 22
}

DATA_TYPE_CONVERSION = {
    "ts": float,
    "id.orig_p": int,
    "id.resp_p": int,
    "duration": float,
    "orig_bytes": int,
    "resp_bytes": int,
    "missed_bytes": int,
    "orig_pkts": int,
    "orig_ip_bytes": int,
    "resp_pkts": int,
    "resp_ip_bytes": int
}

def split_history(text: str) -> List[int]:
    """Split a string containing at most one of the following letters: ShADadFf into a one hot encoding of the letters

    Args:
        text (str): The text to parse

    Returns:
        List[int]: A list containing 1s or 0s based on the presence of each of the letters in: ShADadFf
    """
    if type(text) != str:
        return [0, 0, 0, 0, 0, 0, 0, 0]
    out = {
        "S": 0,
        "h": 0,
        "A": 0,
        "D": 0,
        "a": 0,
        "d": 0,
        "F": 0,
        "f": 0
        }
    
    for letter in text:
        out[letter] = 1
    
    return list(out.values())


def split_ip(ip_address: str) -> List[int]:
    """splits an ip address up into its 4 integer sections

    Args:
        ip_address (str): An ip address the the following format: int.int.int.int as a string

    Returns:
        List[int]: A list containing the different integer parts of the ip address
    """
    split_ip = ip_address.split(".")
    
    split_ip = list(map(int, split_ip))
    
    return split_ip
    


remove_end = lambda x: x.strip("\n")


# open the file 
with open(locations[0]) as f:
    lines = f.readlines()

    # read the column headings and data types
    column_headings = lines[6].split()[1:]
    
    column_types = lines[7].split()[1:]
    
    # extract the data
    data_rows = [list(map(remove_end,line.split())) for line in lines[8:]]
        

# create a pandas dataframe
df = pd.DataFrame(data_rows, columns=column_headings)

# remove bad rows
df = df[df["ts"] != "#close"]

# encode str values at ints representing each of the str classes
for heading, encodings in DATA_ENCODING_DICTIONARY.items():
    df[heading].replace(encodings.keys(), encodings.values(), inplace=True)
    
# convert non-int characters in each of the rows into appropriate int
for heading, encodings in DATA_CONVERSION_DICTIONARY.items():
    df[heading].replace(encodings.keys(), encodings.values(), inplace=True)

# convert the str columns to int and float where required
for heading, function in DATA_TYPE_CONVERSION.items():
    df[heading].apply(lambda x: function(x))


# split the history column into one hot encoding for each of the possible chars in history

# create a temp column with the values of each of the future columns split in a list
df["history_unpacked"] = df["history"].map(lambda x: split_history(x))

df['S'] = df["history_unpacked"].apply(lambda x: x[0])
df['h'] = df["history_unpacked"].apply(lambda x: x[1])
df['A'] = df["history_unpacked"].apply(lambda x: x[2])
df['D'] = df["history_unpacked"].apply(lambda x: x[3])
df['a'] = df["history_unpacked"].apply(lambda x: x[4])
df['d'] = df["history_unpacked"].apply(lambda x: x[5])
df['F'] = df["history_unpacked"].apply(lambda x: x[6])
df['f'] = df["history_unpacked"].apply(lambda x: x[7])

df = df.drop("history", axis=1)
df = df.drop("history_unpacked", axis=1)

# split the two ip address column into a column for each section of the address -> so that its understandable to a machine learning alg

# create a temp column with the values of each of the future columns split in a list
df["id.orig_h_unpacked"] = df["id.orig_h"].map(lambda x: split_ip(x))

df["id.orig_h_a"] = df["id.orig_h_unpacked"].apply(lambda x: x[0])
df["id.orig_h_b"] = df["id.orig_h_unpacked"].apply(lambda x: x[1])
df["id.orig_h_c"] = df["id.orig_h_unpacked"].apply(lambda x: x[2])
df["id.orig_h_d"] = df["id.orig_h_unpacked"].apply(lambda x: x[3])

df = df.drop("id.orig_h", axis=1)
df = df.drop("id.orig_h_unpacked", axis=1)

df["id.resp_h_unpacked"] = df["id.resp_h"].map(lambda x: split_ip(x))

df["id.resp_h_a"] = df["id.resp_h_unpacked"].apply(lambda x: x[0])
df["id.resp_h_b"] = df["id.resp_h_unpacked"].apply(lambda x: x[1])
df["id.resp_h_c"] = df["id.resp_h_unpacked"].apply(lambda x: x[2])
df["id.resp_h_d"] = df["id.resp_h_unpacked"].apply(lambda x: x[3])

df = df.drop("id.resp_h", axis=1)
df = df.drop("id.resp_h_unpacked", axis=1)

print(df.head)
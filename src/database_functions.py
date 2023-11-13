from typing import List
import pandas as pd

from data_helper_functions import get_IP_columns, split_history

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
        "Benign": 0,
        "benign": 0,
        "Malicious": 1,
        "malicious": 1
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

def load_dataset(file_locations) -> pd.DataFrame:
    """ Loads the various datasets and convets them into a single pandas dataframe

    Returns:
        pd.DataFrame: the combined dataframe containing all of the data accross the sub datasets
    """
    remove_end = lambda x: x.strip("\n")

    data_rows = []

    for location in file_locations:
        # open the file 
        with open(location) as f:
            lines = f.readlines()

            # read the column headings and data types
            column_headings = lines[6].split()[1:]
            
            column_types = lines[7].split()[1:]
            
            # extract the data
            data_rows.extend([list(map(remove_end,line.split())) for line in lines[8:]])
            

    # create a pandas dataframe
    df = pd.DataFrame(data_rows, columns=column_headings)
    
    return df


def clean_dataset(df:pd.DataFrame) -> pd.DataFrame:
    """ Cleans the dataframe in various ways:
        - encodes columns with string values into integers
        - converts string values to ints or floats
        - removes rows with bad values

    Args:
        df (pd.DataFrame): _description_

    Returns:
        pd.DataFrame: _description_
    """
    # remove bad rows
    # copy is used to remove the SettingWithCopyWarings by telling pandas that this is a new dataframe and not a view
    df = df[df["ts"] != "#close"].copy()

    # encode str values at ints representing each of the str classes
    for heading, encodings in DATA_ENCODING_DICTIONARY.items():
        df[heading].replace(encodings.keys(), encodings.values(), inplace=True)
        
    # converts bad characters in each of the rows into appropriate new values 
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
    df["id.orig_h_unpacked"] = df["id.orig_h"].map(lambda x: get_IP_columns(x))

    df["id.orig_h_v4a"] = df["id.orig_h_unpacked"].apply(lambda x: x[0])
    df["id.orig_h_v4b"] = df["id.orig_h_unpacked"].apply(lambda x: x[1])
    df["id.orig_h_v4c"] = df["id.orig_h_unpacked"].apply(lambda x: x[2])
    df["id.orig_h_v4d"] = df["id.orig_h_unpacked"].apply(lambda x: x[3])

    df["id.orig_h_v6a"] = df["id.orig_h_unpacked"].apply(lambda x: x[4])
    df["id.orig_h_v6b"] = df["id.orig_h_unpacked"].apply(lambda x: x[5])
    df["id.orig_h_v6c"] = df["id.orig_h_unpacked"].apply(lambda x: x[6])
    df["id.orig_h_v6d"] = df["id.orig_h_unpacked"].apply(lambda x: x[7])
    df["id.orig_h_v6e"] = df["id.orig_h_unpacked"].apply(lambda x: x[8])
    df["id.orig_h_v6f"] = df["id.orig_h_unpacked"].apply(lambda x: x[9])
    df["id.orig_h_v6g"] = df["id.orig_h_unpacked"].apply(lambda x: x[10])
    df["id.orig_h_v6h"] = df["id.orig_h_unpacked"].apply(lambda x: x[11])

    df = df.drop("id.orig_h", axis=1)
    df = df.drop("id.orig_h_unpacked", axis=1)

    df["id.resp_h_unpacked"] = df["id.resp_h"].map(lambda x: get_IP_columns(x))

    df["id.resp_h_v4a"] = df["id.resp_h_unpacked"].apply(lambda x: x[0])
    df["id.resp_h_v4b"] = df["id.resp_h_unpacked"].apply(lambda x: x[1])
    df["id.resp_h_v4c"] = df["id.resp_h_unpacked"].apply(lambda x: x[2])
    df["id.resp_h_v4d"] = df["id.resp_h_unpacked"].apply(lambda x: x[3])

    df["id.resp_h_v6a"] = df["id.resp_h_unpacked"].apply(lambda x: x[4])
    df["id.resp_h_v6b"] = df["id.resp_h_unpacked"].apply(lambda x: x[5])
    df["id.resp_h_v6c"] = df["id.resp_h_unpacked"].apply(lambda x: x[6])
    df["id.resp_h_v6d"] = df["id.resp_h_unpacked"].apply(lambda x: x[7])
    df["id.resp_h_v6e"] = df["id.resp_h_unpacked"].apply(lambda x: x[8])
    df["id.resp_h_v6f"] = df["id.resp_h_unpacked"].apply(lambda x: x[9])
    df["id.resp_h_v6g"] = df["id.resp_h_unpacked"].apply(lambda x: x[10])
    df["id.resp_h_v6h"] = df["id.resp_h_unpacked"].apply(lambda x: x[11])

    df = df.drop("id.resp_h", axis=1)
    df = df.drop("id.resp_h_unpacked", axis=1)


    return df

def select_data_for_training(
        df: pd.DataFrame, 
        headings:List[str] = [
            "ts",
            "id.orig_p",
            "id.resp_p",
            "proto",
            "service",
            "duration",
            "orig_bytes",
            "conn_state",
            "local_orig",
            "missed_bytes",
            "orig_pkts",
            "orig_ip_bytes",
            "resp_pkts",
            "resp_ip_bytes",
            "id.orig_h_v4a",
            "id.orig_h_v4b",
            "id.orig_h_v4c",
            "id.orig_h_v4d",
            "id.orig_h_v6a",
            "id.orig_h_v6b",
            "id.orig_h_v6c",
            "id.orig_h_v6d",
            "id.orig_h_v6e",
            "id.orig_h_v6f",
            "id.orig_h_v6g",
            "id.orig_h_v6h",
            "id.resp_h_v4a",
            "id.resp_h_v4b",
            "id.resp_h_v4c",
            "id.resp_h_v4d",
            "id.resp_h_v6a",
            "id.resp_h_v6b",
            "id.resp_h_v6c",
            "id.resp_h_v6d",
            "id.resp_h_v6e",
            "id.resp_h_v6f",
            "id.resp_h_v6g",
            "id.resp_h_v6h",
        ]
                             ):
    return df[headings], df["label"], df["detailed-label"]


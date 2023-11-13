from database_functions import load_dataset, clean_dataset


locations = [
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled"
]


df = load_dataset(locations)

df = clean_dataset(df)


train=df.sample(frac=0.8,random_state=200)
test=df.drop(train.index)

print(train.size)
print(test.size)
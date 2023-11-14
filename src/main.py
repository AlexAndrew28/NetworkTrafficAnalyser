import sklearn
import matplotlib.pyplot as plt
from sklearn import svm
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import ConfusionMatrixDisplay, classification_report
from sklearn.preprocessing import StandardScaler  


from nn_model import NeuralNetwork
from database_functions import load_dataset, clean_dataset, select_data_for_training


locations = [
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled",
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled",
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled",
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled",
    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-7-1/bro/conn.log.labeled",
#    "src/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled"
]

print("Loading Dataset")

df = load_dataset(locations)

print("Cleaning up data")

df = clean_dataset(df)


train=df.sample(frac=0.8,random_state=200)
test=df.drop(train.index)

print("Training dataset size: ", train.size)
print("Testing dataset size: ", test.size)

train_x, train_y, train_y_detailed = select_data_for_training(train)
test_x, test_y, test_y_detailed = select_data_for_training(test)


#scaler = StandardScaler() 
#scaler.fit(train_x) 
#train_x = scaler.transform(train_x)  
#test_x = scaler.transform(test_x)  

sklearn = False


if sklearn:
    print("Initialising model")

    model = svm.SVC()

    print("Training")

    model.fit(train_x, train_y)

    pred = model.predict(test_x)

    print(classification_report(test_y, pred, target_names=["Benign", "Malicious"]))

    disp = ConfusionMatrixDisplay.from_predictions(test_y, pred)

    disp.plot()

    
else:
    print("Initialising model")
    
    input_size = train_x.shape[1]
    output_size = 2

    model = NeuralNetwork(input_size, output_size)

    print("Training")

    model.train(train_x, train_y, test_x, test_y, n_epochs=10)
    
    acc, pred, true = model.test(test_x, test_y)
    
    disp = ConfusionMatrixDisplay.from_predictions(test_y, pred, display_labels=["Benign", "Malicious"])

    disp.plot()
    
plt.show()
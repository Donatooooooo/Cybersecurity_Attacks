from Dataset.dataset import Dataset
from KnowledgeBase.kb import KnowledgeBase
from classifier import ModelTrainerClass
from classifier_MLP import ModelTrainer
from preprocessor import prologPreprocessor
from regression import RegressionModelTrainer

"""
MAINTEST
"""
dataset = Dataset("Dataset/cybersecurity_attacks.csv")

print("\n\n *** LOGICAL MODULE *** \n")
plFrame = prologPreprocessor("Dataset/cybersecurity_attacks.csv")
kb = KnowledgeBase("KnowledgeBase/main.pl")
kb.computeBasescore(plFrame)
dataset.addDatasetColumn("Basescore", kb.getBasescore())
dataset.saveDataset("Dataset/BaseScore_cybersecurity_attacks.csv")

for _, row in plFrame.tail(4).iterrows():
    protocol = row['Protocol']
    packetType = row['Packet Type']
    trafficType = row['Traffic Type']
    malware = row['Malware Indicators']
    attackType = row['Attack Type']
    proxy = row['Proxy Information']
    idsAlerts = row['IDS/IPS Alerts']
    firewall = row['Firewall Logs']
    packetLength = row['Packet Length']
    anomalyScore = row['Anomaly Scores']
    os = row['OS']

    print("--------------------------------------------------------------------------------------------------------------------------------\n")
    print(f"network_event = ('{packetType}', '{trafficType}', '{packetLength}', '{protocol}', '{attackType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{os}', {anomalyScore})\n")
    basescore = kb.askBasescore(packetType, trafficType, packetLength, protocol, attackType, firewall, idsAlerts, malware, proxy, os)
    impact = kb.askImpact(packetType, trafficType, packetLength, protocol)
    exploit = kb.askExploitability(protocol, attackType, packetType, firewall, idsAlerts, malware, proxy, trafficType, os)
    isSafe = kb.isSafeEvent(packetType, trafficType, packetLength, protocol, attackType, firewall, idsAlerts, malware, proxy, os, anomalyScore)

    print("BASESCORE: ", basescore, ", IMPACT: ", impact, ", EXPLOITABILITY: ", exploit)
    print(isSafe)


print("\n\n *** CLASSIFIERS MODULE *** \n\n")
trainer_MLP = ModelTrainer("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'])
X, y = trainer_MLP.load_and_preprocess_data()
trainer_MLP.train_model_MLP(X, y, 'MLP')
trainer = ModelTrainerClass("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'])
trainer.run()
additional_features=['Attack Type_Intrusion', 'Attack Type_Malware', 'Malware Indicators', 'Anomaly Scores', 'Alerts/Warnings', 'IDS/IPS Alerts', 'Proxy Information', 'Firewall Logs', 'Packet Type_Data', 'Action Taken_Ignored', 'Action Taken_Logged', 'Traffic Type_FTP', 'Traffic Type_HTTP', 'Log Source_Server']
trainer_KNN = ModelTrainerClass("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'],additional_features=additional_features)
trainer_KNN.train_model_KNN('KNN')


print("\n\n *** REGRESSION MODULE *** \n\n")
trainer_regressor = RegressionModelTrainer("Dataset/BaseScore_cybersecurity_attacks.csv", 'Basescore', ['Basescore'])
X_train, X_test, y_train, y_test = trainer_regressor.load_and_preprocess_data()
model = trainer_regressor.build_model(X_train.shape[1])
trainer_regressor.train_model(model, X_train, y_train)
trainer_regressor.evaluate_model(model, X_test, y_test)


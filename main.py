from Dataset.dataset import Dataset
from KnowledgeBase.kb import KnowledgeBase, query
from Models.classifiers import ModelTrainerClass
from preprocessor import prologPreprocessor
from Models.MLP import RegressionModelTrainer

dataset = Dataset("Dataset/cybersecurity_attacks.csv")

plFrame = prologPreprocessor("Dataset/cybersecurity_attacks.csv")
kb = KnowledgeBase("KnowledgeBase/main.pl")
kb.computeBasescore(plFrame)
dataset.addDatasetColumn("Basescore", kb.getBasescore())
dataset.saveDataset("Dataset/BaseScore_cybersecurity_attacks.csv")

knowledge = query(kb, plFrame)
print(knowledge)

trainer = ModelTrainerClass(
    "Dataset/BaseScore_cybersecurity_attacks.csv", "Protocol", ["Protocol"]
)
trainer.run()
additional_features = [
    "Attack Type_Intrusion",
    "Attack Type_Malware",
    "Malware Indicators",
    "Anomaly Scores",
    "Alerts/Warnings",
    "IDS/IPS Alerts",
    "Proxy Information",
    "Firewall Logs",
    "Packet Type_Data",
    "Action Taken_Ignored",
    "Action Taken_Logged",
    "Traffic Type_FTP",
    "Traffic Type_HTTP",
    "Log Source_Server",
]
trainer_KNN = ModelTrainerClass(
    "Dataset/BaseScore_cybersecurity_attacks.csv",
    "Protocol",
    ["Protocol"],
    additional_features=additional_features,
)
trainer_KNN.train_model_KNN("KNN")

trainer_regressor = RegressionModelTrainer(
    "Dataset/BaseScore_cybersecurity_attacks.csv", "Basescore", ["Basescore"]
)
X_train, X_test, y_train, y_test = trainer_regressor.load_and_preprocess_data()
model = trainer_regressor.build_model(X_train.shape[1])
trainer_regressor.train_model(model, X_train, y_train)
trainer_regressor.evaluate_model(model, X_test, y_test)
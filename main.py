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

print("\n\n *** COMPUTING BASESCORE *** \n\n")
plFrame = prologPreprocessor()
kb = KnowledgeBase("KnowledgeBase/rules.pl")
kb.computeBasescore(plFrame)

dataset.addDatasetColumn("Basescore", kb.getBasescore())
dataset.saveDataset("Dataset/BaseScore_cybersecurity_attacks.csv")

print("\n\n *** CLASSIFIERS *** \n\n")
trainer = ModelTrainerClass("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'])
trainer_MLP = ModelTrainer("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'])
X, y = trainer_MLP.load_and_preprocess_data()
trainer_MLP.train_model_MLP(X, y, 'MLP')
trainer.run()

print("\n\n *** REGRESSION *** \n\n")
trainer = RegressionModelTrainer("Dataset/BaseScore_cybersecurity_attacks.csv", 'Basescore', ['Basescore'])
X_train, X_test, y_train, y_test = trainer.load_and_preprocess_data()
model = trainer.build_model(X_train.shape[1])
trainer.train_model(model, X_train, y_train)
trainer.evaluate_model(model, X_test, y_test)

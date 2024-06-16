from Dataset.dataset import Dataset
from KnowledgeBase.prologManager import PrologManager
from classifier import ModelTrainerClass
from classifier_MLP import ModelTrainer
from preprocessor import prologPreprocessor
from regression import RegressionModelTrainer

"""
MAINTEST
"""
dataset = Dataset("Dataset/cybersecurity_attacks.csv")

plFrame = prologPreprocessor()
prolog = PrologManager("KnowledgeBase/rules.pl")
prolog.computeBasescore(plFrame)

dataset.addDatasetColumn("Basescore", prolog.getBasescore())
dataset.saveDataset("Dataset/BaseScore_cybersecurity_attacks.csv")

#Classifier
trainer = ModelTrainerClass("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'])
trainer_MLP = ModelTrainer("Dataset/BaseScore_cybersecurity_attacks.csv", 'Protocol', ['Protocol'])
X, y = trainer_MLP.load_and_preprocess_data()
trainer_MLP.train_model_MLP(X, y, 'MLP')
trainer.run()

#Regression
trainer = RegressionModelTrainer("Dataset/BaseScore_cybersecurity_attacks.csv", 'Basescore', ['Basescore'])
X_train, X_test, y_train, y_test = trainer.load_and_preprocess_data()
model = trainer.build_model(X_train.shape[1])
trainer.train_model(model, X_train, y_train)
trainer.evaluate_model(model, X_test, y_test)

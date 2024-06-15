from Dataset.dataset import Dataset
from KnowledgeBase.prologManager import PrologManager
from classifier import classifier
from regression import regression
from preprocessor import *

"""
MAINTEST
"""
dataset = Dataset("Dataset/cybersecurity_attacks.csv")

plFrame = prologPreprocessor()
prolog = PrologManager("KnowledgeBase/rules.pl")
prolog.computeBasescore(plFrame)

dataset.addDatasetColumn("Basescore", prolog.getBasescore())
dataset = datasetPreprocessor(dataset)
dataset.saveDataset("Dataset/Altered_cybersecurity_attacks.csv")



# dataset = Dataset("Dataset/Altered_cybersecurity_attacks.csv")
# features = dataset.getDataFrame(['Malware Indicators', 'Anomaly Scores', 'Alerts/Warnings', 'Severity Level_Low',
#                                     'Severity Level_Medium','Attack Type_Intrusion', 'Attack Type_Malware', 'Traffic Type_FTP', 'Traffic Type_HTTP'])
# kmeans = kMeans().clustering(features, "Attack")
# dataset.addDatasetColumn('Own Cluster', kmeans.fit_predict(features))
# dataset.saveDataset("Dataset/Clusterized_dataset.csv")


#Classifier
classifier()

#Regression
regression()

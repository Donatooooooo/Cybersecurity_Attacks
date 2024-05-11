from Dataset.dataset import Dataset
from preprocessor import datasetPreprocessor
from kmeans import kMeans

"""
MAINTEST
"""
dataset = Dataset("Dataset/cybersecurity_attacks.csv")
datasetPreprocessor(dataset)

dataset = Dataset("Dataset/Altered_cybersecurity_attacks.csv")
features = dataset.getDataFrame(['Malware Indicators', 'Anomaly Scores', 'Alerts/Warnings', 'Severity Level_Low',
                                    'Severity Level_Medium','Attack Type_Intrusion', 'Attack Type_Malware', 'Traffic Type_FTP', 'Traffic Type_HTTP'])
kmeans = kMeans().clustering(features, "Attack")
dataset.addDatasetColumn('Own Cluster', kmeans.fit_predict(features))
dataset.saveDataset("Dataset/Clusterized_dataset.csv")

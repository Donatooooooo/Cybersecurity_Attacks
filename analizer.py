from Dataset.dataset import Dataset
from preprocessor import emptyValues
from pyswip import Prolog
import pandas, sys, os

def Preprocessor():
    dataset = Dataset('Dataset/cybersecurity_attacks.csv')
    dataset.dropDatasetColumns(['Source IP Address', 'Timestamp', 'Destination IP Address', 'Payload Data', 
                                    'Attack Signature', 'User Information', 'Network Segment', 'Geo-location Data',
                                         'Device Information', 'Timestamp','Source Port','Destination Port',
                                            'Packet Length', 'Severity Level','Log Source', 'Firewall Logs'])
    dataset = emptyValues(dataset)
    dataset = dataset.getDataset()
    dataset['Proxy Information'] = dataset['Proxy Information'].apply(lambda x: 1 if pandas.notna(x) else 0)
    return dataset


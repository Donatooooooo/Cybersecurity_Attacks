from Dataset.dataset import Dataset
from preprocessor import emptyValues
import pandas 

def write_prolog_fact(record):
    fields = record.split(',')
    fact = "network_event("
    for field in fields:
        if field.isdigit():
            fact += field + ","
        elif field.replace('.', '', 1).isdigit():
            fact += field + ","
        else:
            fact += "'" + field + "',"
    fact = fact[:-1] + ")."
    return fact

def factWriter():
    dataset = Dataset('Dataset/cybersecurity_attacks.csv')
    dataset.dropDatasetColumns([
        'Source IP Address', 'Timestamp', 'Destination IP Address', 
        'Payload Data', 'Attack Signature', 'User Information', 
        'Network Segment', 'Geo-location Data', 'Device Information', 
        'Timestamp','Source Port','Destination Port', 'Packet Length', 
        'Severity Level', 'Log Source'
    ])
    
    dataset = emptyValues(dataset)
    dataset = dataset.getDataset()
    dataset['Proxy Information'] = dataset['Proxy Information'].apply(lambda x: 1 if pandas.notna(x) else 0)

    
    with open('Prolog/kb.pl', 'w') as file:
        for index, row in dataset.iterrows():
            record = ','.join(map(str, row.tolist()))
            fact = write_prolog_fact(record)
            file.write(fact + '\n')

# Esegui la funzione factWriter per scrivere i fatti nel file Prolog
factWriter()
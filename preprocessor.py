from dataset import Dataset
import pandas
import re

def searchEngine(userAgent):
    browserPattern = re.compile(r'Mozilla.*?(Firefox|Chrome|MSIE|Safari)', re.IGNORECASE)
    browserMatch = browserPattern.search(userAgent)
    if browserMatch:
        return browserMatch.group(1)
    else:
        return "Opera"

def os(userAgent):
    osPattern = re.compile(r'(Windows|Macintosh|Linux|iPhone|iPad|iPod|Android)', re.IGNORECASE)
    osMatch = osPattern.search(userAgent)
    if osMatch:
        if osMatch.group(1).startswith('i'):
            return 'iOS'
        if osMatch.group(1).startswith('M'):
            return 'macOS'
        else:
            return osMatch.group(1)
    else:
        return "Unknown"

def datasetPreprocessor(dataset: Dataset):
    data = dataset.getDataset()
    data['Timestamp'] = pandas.to_datetime(data['Timestamp'])
    data.insert(0, 'Time',  data['Timestamp'].dt.time)
    data.insert(0, 'Date',  data['Timestamp'].dt.date)
    
    data['Proxy Information'] = data['Proxy Information'].apply(lambda x: 1 if pandas.notna(x) else 0)
    data['Search Engine'] = data['Device Information'].apply(lambda x: searchEngine(x) if pandas.notnull(x) else None)
    data['OS'] = data['Device Information'].apply(lambda x: os(x) if pandas.notnull(x) else None)
    
    dataset.setDataset(data)
    dataset.alterDatasetColumns(['Source IP Address', 'Timestamp', 'Destination IP Address', 
                                    'Payload Data', 'Attack Signature', 'User Information', 
                                        'Network Segment', 'Geo-location Data', 'Device Information'])

    dataset.emptyValues('Alerts/Warnings', 'Alert Triggered')
    dataset.emptyValues('Malware Indicators', 'IoC Detected')
    dataset.emptyValues('Firewall Logs', 'Log Data')
    dataset.emptyValues('IDS/IPS Alerts', 'Alert Data')
    
    dataset.getDummies('Packet Type')
    dataset.getDummies('Protocol')
    dataset.getDummies('Action Taken')
    dataset.getDummies('Severity Level')
    dataset.getDummies('Attack Type')
    dataset.getDummies('Traffic Type')
    dataset.getDummies('Log Source')
    
    dataset.replaceBoolean()
    
    dataset.saveDataset("Dataset/Altered_cybersecurity_attacks.csv")


"""
TEST
"""
datasetPreprocessor(Dataset("Dataset/cybersecurity_attacks.csv"))
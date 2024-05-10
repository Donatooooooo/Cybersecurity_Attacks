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
    osPattern = re.compile(r'(Windows|Mac OS|Linux|iPhone OS|iPad OS|iPod OS|Android)', re.IGNORECASE)
    osMatch = osPattern.search(userAgent)
    if osMatch:
        return osMatch.group(1)
    else:
        return "Unknown"

def datasetPreprocessor(dataset: Dataset):
    data = dataset.getDataset()
    data['Timestamp'] = pandas.to_datetime(data['Timestamp'])
    data.insert(0, 'Hour',  data['Timestamp'].dt.hour)
    data.insert(0, 'Minute',  data['Timestamp'].dt.minute)
    data.insert(0, 'Year',  data['Timestamp'].dt.year)
    data.insert(0, 'Month',  data['Timestamp'].dt.month)
    data.insert(0, 'Day',  data['Timestamp'].dt.day)
    
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
    
    dataset.normalizeColumn('Hour')
    dataset.normalizeColumn('Minute')
    dataset.normalizeColumn('Year')
    dataset.normalizeColumn('Month')
    dataset.normalizeColumn('Day')
    dataset.normalizeColumn('Source Port')
    dataset.normalizeColumn('Destination Port')
    dataset.normalizeColumn('Packet Length')
    dataset.normalizeColumn('Anomaly Scores')
    
    dataset.saveDataset("Dataset/Altered_cybersecurity_attacks.csv")

"""
TEST
"""
datasetPreprocessor(Dataset("Dataset/cybersecurity_attacks.csv"))
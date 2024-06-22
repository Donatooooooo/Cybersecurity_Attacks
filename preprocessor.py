from Dataset.dataset import Dataset
from Util.Exceptions import userAgentException
import pandas, sys, re

def browser(userAgent):
    browserPattern = re.compile(r'Mozilla.*?(Firefox|Chrome|MSIE|Safari)', re.IGNORECASE)
    browserMatch = browserPattern.search(userAgent)
    if browserMatch:
        return browserMatch.group(1)
    elif userAgent.startswith("Opera"):
        return "Opera"
    else:
        raise userAgentException(userAgent)

def os(userAgent):
    osPattern = re.compile(r'(Windows|Mac OS|Linux|iPhone OS|iPad OS|iPod OS|Android)', re.IGNORECASE)
    osMatch = osPattern.search(userAgent)
    if osMatch:
        return osMatch.group(1)
    else:
        raise userAgentException(userAgent)

def basicPreprocessing(dataset: Dataset):
    data = dataset.getDataset()
    
    data['Proxy Information'] = data['Proxy Information'].apply(lambda x: 1 if pandas.notna(x) else 0)
    try:
        data['Browser'] = data['Device Information'].apply(lambda x: browser(x) if pandas.notnull(x) else None)
        data['OS'] = data['Device Information'].apply(lambda x: os(x) if pandas.notnull(x) else None)
    except userAgentException as e:
        print(e)
        sys.exit(1)
    dataset.setDataset(data)
    dataset.dropDatasetColumns(['Source IP Address', 'Timestamp', 'Destination IP Address', 
                                    'Payload Data', 'Attack Signature', 'User Information', 'Severity Level', 
                                        'Network Segment', 'Geo-location Data', 'Device Information'])
    return dataset

def emptyValues(dataset: Dataset):
    dataset.emptyValues('Alerts/Warnings', 'Alert Triggered')
    dataset.emptyValues('Malware Indicators', 'IoC Detected')
    dataset.emptyValues('Firewall Logs', 'Log Data')
    dataset.emptyValues('IDS/IPS Alerts', 'Alert Data')
    return dataset

def getDummies(dataset: Dataset):
    dataset.getDummies('Packet Type')
    dataset.getDummies('Action Taken')
    dataset.getDummies('Attack Type')
    dataset.getDummies('Traffic Type')
    dataset.getDummies('Log Source')
    dataset.getDummies('OS')
    dataset.getDummies('Browser')
    return dataset

def normalizeColumns(dataset: Dataset):
    dataset.normalizeColumn('Source Port')
    dataset.normalizeColumn('Destination Port')
    dataset.normalizeColumn('Packet Length')
    dataset.normalizeColumn('Anomaly Scores')
    dataset.normalizeColumn('Basescore')
    return dataset

def prologPreprocessor(path):
    dataset = Dataset(path).getDataset()
    dataset['Proxy Information'] = dataset['Proxy Information'].apply(lambda x: 'Proxy' if pandas.notna(x) else 'None')
    
    mean = dataset['Packet Length'].mean()
    dataset['Packet Length'] = dataset['Packet Length'].apply(lambda x: 'Long' if x>mean else 'Short')
    
    try:
        dataset['OS'] = dataset['Device Information'].apply(lambda x: os(x) if pandas.notnull(x) else None)
    except userAgentException as e:
        print(e)
        sys.exit(1)

    dataset['Anomaly Scores'] = round(dataset['Anomaly Scores'])
    dataset['Alerts/Warnings'] = dataset['Alerts/Warnings'].fillna('None')
    dataset['Malware Indicators'] = dataset['Malware Indicators'].fillna('None')
    dataset['Firewall Logs'] = dataset['Firewall Logs'].fillna('None')
    dataset['IDS/IPS Alerts'] = dataset['IDS/IPS Alerts'].fillna('None')
    
    dataset = dataset.drop(columns=['Source IP Address', 'Timestamp', 'Destination IP Address', 'Log Source',  'Network Segment',
                                        'Payload Data', 'Attack Signature', 'User Information', 'Severity Level', 'Alerts/Warnings',
                                            'Geo-location Data', 'Device Information', 'Destination Port', 'Source Port'])
    return dataset

def datasetPreprocessor(dataset: Dataset):
    dataset = basicPreprocessing(dataset)
    dataset = emptyValues(dataset)
    dataset = normalizeColumns(dataset)
    dataset = getDummies(dataset)
    dataset.replaceBoolean()
    return dataset


def datasetPreprocessor_regressor(dataset: Dataset):
    dataset = datasetPreprocessor(dataset)
    dataset.getDummies('Protocol')
    return dataset
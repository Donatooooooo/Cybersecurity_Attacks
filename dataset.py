import pandas

def importDataset(path):
    return pandas.read_csv(path)

def alterDatasetColumns(dataset, columnsToRemove):
    return dataset.drop(columns = columnsToRemove)

def saveDataset(dataset, path):
    dataset.to_csv(path, index=False)

def preprocessing():
    dataset = importDataset("cybersecurity_attacks.csv")
    
    #analisi dell'unicità
    unique_values = dataset.nunique()
    length = len(dataset)
    unique_values = unique_values/length
    unique_values.to_csv("unique_values.csv")
    
    #analisi dei valori nulli
    missing_values = dataset.isnull().sum()
    missing_values.to_csv("missing_values.csv")

    #Conversione delle colonne
    dataset['Timestamp'] = pandas.to_datetime(dataset['Timestamp'])
    dataset.insert(0, 'Time',  dataset['Timestamp'].dt.time)
    dataset.insert(0, 'Date',  dataset['Timestamp'].dt.date)
    
    dataset = alterDatasetColumns(dataset, ['Source IP Address', 'Timestamp', 'Destination IP Address', 'Payload Data', 'Attack Signature', 'User Information', 'Network Segment', 'Geo-location Data',])
    
    
    #gestione elementi vuoti nelle colonne 
    dataset['Alerts/Warnings'] =  dataset['Alerts/Warnings'].replace('Alert Triggered', 1).fillna(0)
    dataset['Malware Indicators'] =  dataset['Malware Indicators'].replace('IoC Detected', 1).fillna(0)
    dataset['Firewall Logs'] =  dataset['Firewall Logs'].replace('Log Data', 1).fillna(0)
    dataset['IDS/IPS Alerts'] =  dataset['IDS/IPS Alerts'].replace('Alert Data', 1).fillna(0)
    
    dataset['Proxy Information'] = dataset['Proxy Information'].apply(lambda x: 1 if pandas.notna(x) else 0)
    
    dataset = pandas.get_dummies(dataset, columns=['Packet Type'], drop_first=True)
    dataset = pandas.get_dummies(dataset, columns=['Protocol'], drop_first=True)
    dataset = pandas.get_dummies(dataset, columns=['Action Taken'], drop_first=True)
    dataset = pandas.get_dummies(dataset, columns=['Severity Level'], drop_first=True)
    dataset = pandas.get_dummies(dataset, columns=['Attack Type'], drop_first=True)
    dataset = pandas.get_dummies(dataset, columns=['Traffic Type'], drop_first=True)
    dataset = pandas.get_dummies(dataset, columns=['Log Source'], drop_first=True)
    
    dataset = dataset.replace({True:1, False:0})
       
    motori_di_ricerca = ["Mozilla", "Opera", "Chrome", "Safari"]
    sistemi_operativi = ["Windows", "Macintosh", "Linux", "Android", "iPhone", "iPad", "iPod"]
    
    def trova_motore(descrizione): 
        for motore in motori_di_ricerca:
            if motore in descrizione:
                return motore
        return None

    def trova_sistema(descrizione):
        for sistema in sistemi_operativi:
            if sistema in descrizione:
                if (sistema.startswith('i')):
                    return 'iOS'
                if (sistema.startswith('M')):
                    return 'macOS'
                else:
                    return sistema
        return None

    dataset['MotoreDiRicerca'] = dataset['Device Information'].apply(lambda x: trova_motore(x) if pandas.notnull(x) else None)
    dataset['SistemaOperativo'] = dataset['Device Information'].apply(lambda x: trova_sistema(x) if pandas.notnull(x) else None)
    dataset = dataset.drop(columns = 'Device Information')
    
    saveDataset(dataset, "Altered_cybersecurity_attacks_prova.csv")
    
preprocessing()
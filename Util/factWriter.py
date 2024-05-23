from preprocessor import prologPreprocessor

def factWriter(dataset):
    attackComplexity = set()
    privilegesRequired = set()
    userInteraction = set()
    confidentiality = set()
    integrity = set()
    
    for _, row in dataset.iterrows():
        attackComplexity.add((row['Protocol'], row['Attack Type'], row['Packet Type'], row['Firewall Logs'], 
                                    row['IDS/IPS Alerts'], row['Malware Indicators']))
        privilegesRequired.add((row['Proxy Information'], row['Attack Type'], row['Traffic Type'], row['OS']))
        userInteraction.add((row['Attack Type'], row['Action Taken']))
        confidentiality.add((row['Packet Type'], row['Traffic Type'], row['Packet Length']))
        integrity.add((row['Packet Type'], row['Protocol']))

    with open('Prolog/kb.pl', 'w') as file:
        for data in attackComplexity:
            score = sum(complexityScore(value) for value in data)
            file.write(f"access_complexity('{data[0]}', '{data[1]}', '{data[2]}', '{data[3]}', '{data[4]}', '{data[5]}', {score}).\n")
        file.write("\n")
        for data in privilegesRequired:
            score = sum(privilegesScore(value) for value in data)
            file.write(f"authentication('{data[0]}', '{data[1]}', '{data[2]}', '{data[3]}', {score}).\n")
        file.write("\n")    
        for data in userInteraction:
            score = sum(interactionScore(value) for value in data)
            file.write(f"user_interaction('{data[0]}', '{data[1]}', {score}).\n")
        file.write("\n")
        for data in confidentiality:
            score = sum(confidentialityScore(value) for value in data)
            file.write(f"confidential_impact('{data[0]}', '{data[1]}', '{data[2]}', {score}).\n")
        file.write("\n")
        for data in integrity:
            score = sum(integrityScore(value) for value in data)
            file.write(f"integrity_impact('{data[0]}', '{data[1]}', {score}).\n")
            
def complexityScore(item):
    scores = {
       'Control': 1,
       'Data': 2,
       'TCP': 2,
       'ICMP': 1,
       'UDP': 1,
       'DDoS': 1,
       'Malware': 1,
       'Intrusion': 2,
       'Log Data': 1,
       'Alert Data': 1,
       'Malware Indicators': 1,
       'None': 0
    }
    return scores.get(item, 0)
    
def privilegesScore(item):
    scores = {
       'DDoS': 1,
       'Malware': 2,
       'Intrusion': 2,
       'Proxy': 1,
       'HTTP': 2,
       'FTP': 3,
       'DNS': 1,
       'Windows': 2,
       'iPhone OS':3,
       'iPad OS':3,
       'iPod OS':3,
       'Mac OS':3,
       'Android':2,
       'Linux': 1,
       'None': 0
    }
    return scores.get(item, 0)

def interactionScore(item):
    scores = {
        'DDoS': 1,
        'Malware': 2,
        'Intrusion': 2,
        'Logged': 1,
        'Blocked': 2,
        'Ignored': 2,
        'None': 0
    }
    return scores.get(item, 0)

def confidentialityScore(item):
    scores = {
       'Control': 0,
       'Data': 1,
       'HTTP': 2,
       'FTP': 2,
       'DNS': 1,
       'Short': 0,
       'Long': 1,
       'None': 0
    }
    return scores.get(item, 0)

def integrityScore(item):
    scores = {
       'Control': 0,
       'Data': 1,
       'UDP': 2,
       'TCP': 1,
       'ICMP': 0
    }
    return scores.get(item, 0)
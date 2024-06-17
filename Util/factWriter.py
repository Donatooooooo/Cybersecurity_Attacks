def factWriter(dataset):
    attackComplexity = set()
    privilegesRequired = set()
    confidentiality = set()
    integrity = set()
    
    for _, row in dataset.iterrows():
        attackComplexity.add((row['Protocol'], row['Attack Type'], row['Packet Type'], row['Firewall Logs'], 
                                    row['IDS/IPS Alerts'], row['Malware Indicators']))
        privilegesRequired.add((row['Proxy Information'], row['Attack Type'], row['Traffic Type'], row['OS']))
        confidentiality.add((row['Packet Type'], row['Traffic Type'], row['Packet Length']))
        integrity.add((row['Packet Type'], row['Protocol']))

    with open('KnowledgeBase/test.pl', 'w') as file:
        for data in attackComplexity:
            score = round(sum(complexityScore(value) for value in data), 4)
            file.write(f"access_complexity('{data[0]}', '{data[1]}', '{data[2]}', '{data[3]}', '{data[4]}', '{data[5]}', {score}).\n")
            v.append(score)
        for data in privilegesRequired:
            score = round(sum(privilegesScore(value) for value in data), 4)
            file.write(f"authentication('{data[0]}', '{data[1]}', '{data[2]}', '{data[3]}', {score}).\n")
        file.write("\n")
        for data in confidentiality:
            score = round(sum(confidentialityScore(value) for value in data), 4)
            file.write(f"confidential_impact('{data[0]}', '{data[1]}', '{data[2]}', {score}).\n")
        file.write("\n")
        for data in integrity:
            score = round(sum(integrityScore(value) for value in data), 4)
            file.write(f"integrity_impact('{data[0]}', '{data[1]}', {score}).\n")

def complexityScore(item):
    scores = {
       'Control': 0.1,
       'Data': 0.2,
       'TCP': 0.2,
       'ICMP': 0.1,
       'UDP': 0.15,
       'DDoS': 0.1,
       'Malware': 0.15,
       'Intrusion': 0.2,
       'Log Data': 0.1,
       'Alert Data': 0.15,
       'Malware Indicators': 0.15,
       'None': 0.0
    }
    return scores.get(item, 0)
    
def privilegesScore(item):
    scores = {
       'DDoS': 0.1,
       'Malware': 0.2,
       'Intrusion': 0.2,
       'Proxy': 0.1,
       'HTTP': 0.2,
       'FTP': 0.3,
       'DNS': 0.1,
       'Windows': 0.2,
       'iPhone OS': 0.3,
       'iPad OS': 0.3,
       'iPod OS': 0.3,
       'Mac OS': 0.3,
       'Android': 0.2,
       'Linux': 0.15,
       'None': 0.0
    }
    return scores.get(item, 0)

def confidentialityScore(item):
    scores = {
       'Control': 0.0,
       'Data': 0.1,
       'HTTP': 0.2,
       'FTP': 0.25,
       'DNS': 0.1,
       'Short': 0.0,
       'Long': 0.1,
       'None': 0.0
    }
    return scores.get(item, 0)

def integrityScore(item):
    scores = {
       'Control': 0.0,
       'Data': 0.1,
       'UDP': 0.2,
       'TCP': 0.15,
       'ICMP': 0.0
    }
    return scores.get(item, 0)
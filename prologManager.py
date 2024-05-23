from Dataset.dataset import Dataset
from preprocessor import prologPreprocessor
from pyswip import Prolog

class prologManager():

    def __init__(self, KBpath, dataset):
        self.prolog = Prolog()
        self.prolog.consult(KBpath)
        self.dataset = dataset

    def findScore(self):
        results = []
        for _, row in self.dataset.iterrows():
            protocol = row['Protocol']
            packetType = row['Packet Type']
            trafficType = row['Traffic Type']
            malwareIndicators = row['Malware Indicators']
            alertsWarnings = row['Alerts/Warnings']
            attackType = row['Attack Type']
            actionTaken = row['Action Taken']
            proxyInformation = row['Proxy Information']
            idsAlerts = row['IDS/IPS Alerts']
            firewall = row['Firewall Logs']
            os = row['OS']
            packetLength = row['Packet Length']
            
            query = f"network_event_score('{protocol}', '{packetType}', '{trafficType}', {malwareIndicators}, {alertsWarnings}, '{attackType}', '{actionTaken}', {proxyInformation}, {idsAlerts}, LABEL)."
            queryResults = list(self.prolog.query(query))
            results.extend(queryResults)
        return results

dataset = prologPreprocessor()
prolog = prologManager('Prolog/kb.pl', dataset)
# results = prolog.findScore()

# for item in results:
#     print(item)



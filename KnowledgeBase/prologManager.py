from pyswip import Prolog

class PrologManager():

    def __init__(self, KBpath):
        self.prolog = Prolog()
        self.prolog.consult(KBpath)
        self.basescore = []

    def getBasescore(self):
        return self.basescore

    def computeBasescore(self, frame):
        for _, row in frame.iterrows():
            protocol = row['Protocol']
            packetType = row['Packet Type']
            trafficType = row['Traffic Type']
            malware = row['Malware Indicators']
            attackType = row['Attack Type']
            proxy = row['Proxy Information']
            idsAlerts = row['IDS/IPS Alerts']
            firewall = row['Firewall Logs']
            os = row['OS']
            packetLength = row['Packet Length']
            
            query = f"basescore('{packetType}', '{trafficType}', '{packetLength}', '{protocol}', '{attackType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{os}', BASESCORE)."
            queryResults = list(self.prolog.query(query))
            self.basescore.extend(query['BASESCORE'] for query in queryResults)
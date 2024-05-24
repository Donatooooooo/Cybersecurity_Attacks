from pyswip import Prolog

class PrologManager():

    def __init__(self, KBpath, frame):
        self.prolog = Prolog()
        self.prolog.consult(KBpath)
        self.frame = frame
        self.basescore = []

    def computeBasescore(self):
        for _, row in self.frame.iterrows():
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
            
            query = f"basescore('{packetType}', '{trafficType}', '{packetLength}', '{protocol}', '{attackType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{os}', BASE)."
            queryResults = list(self.prolog.query(query))
            self.basescore.extend(query['BASE'] for query in queryResults)
            
    def getBasescore(self):
        return self.basescore
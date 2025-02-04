from pyswip import Prolog

class KnowledgeBase():

    def __init__(self, KBpath):
        self.prolog = Prolog()
        self.prolog.consult(KBpath)
        self.basescore = []

    def getBasescore(self):
        return self.basescore
    
    def askBasescore(self, packetType, trafficType, packetLength, protocol, attackType, firewall, idsAlerts, malware, proxy, os):
        query = f"basescore('{packetType}', '{trafficType}', '{packetLength}', '{protocol}', '{attackType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{os}', BASESCORE)."
        basescore = list(self.prolog.query(query))
        return basescore[0]['BASESCORE']
    
    def askImpact(self, packetType, trafficType, packetLenght, protocol):
        query = f"impact('{packetType}', '{trafficType}', '{packetLenght}', '{protocol}', IMPACT)."
        impact = list(self.prolog.query(query))
        return impact[0]['IMPACT']
    
    def askExploitability(self, protocol, attackType, packetType, firewall, idsAlerts, malware, proxy, trafficType, os):
        query = f"exploitability('{protocol}', '{attackType}', '{packetType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{trafficType}', '{os}', EXPLOIT)."
        exploit = list(self.prolog.query(query))
        return exploit[0]['EXPLOIT']

    def isSafeEvent(self, packetType, trafficType, packetLength, protocol, attackType, firewall, idsAlerts, malware, proxy, os, anomalyScore):
        query = f"safe_event('{packetType}', '{trafficType}', '{packetLength}', '{protocol}', '{attackType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{os}', {anomalyScore})."
        isSafe = bool(list(self.prolog.query(query)))
        return "+++ Safe Event +++" if isSafe else "--- Risky Event ---"    

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
            
def query(kb, frame):
    for _, row in frame.tail(4).iterrows():
        protocol = row["Protocol"]
        packetType = row["Packet Type"]
        trafficType = row["Traffic Type"]
        malware = row["Malware Indicators"]
        attackType = row["Attack Type"]
        proxy = row["Proxy Information"]
        idsAlerts = row["IDS/IPS Alerts"]
        firewall = row["Firewall Logs"]
        packetLength = row["Packet Length"]
        anomalyScore = row["Anomaly Scores"]
        os = row["OS"]

        impact = kb.askImpact(packetType, trafficType, packetLength, protocol)
        exploit = kb.askExploitability(
            protocol,
            attackType,
            packetType,
            firewall,
            idsAlerts,
            malware,
            proxy,
            trafficType,
            os,
        )
        basescore = kb.askBasescore(
            packetType,
            trafficType,
            packetLength,
            protocol,
            attackType,
            firewall,
            idsAlerts,
            malware,
            proxy,
            os,
        )
        isSafe = kb.isSafeEvent(
            packetType,
            trafficType,
            packetLength,
            protocol,
            attackType,
            firewall,
            idsAlerts,
            malware,
            proxy,
            os,
            anomalyScore,
        )

        output = f"network_event = ('{packetType}', '{trafficType}', '{packetLength}', '{protocol}', '{attackType}', '{firewall}', '{idsAlerts}', '{malware}', '{proxy}', '{os}', {anomalyScore})\n"
        output += (
            f"Impact: {impact}, Exploit: {exploit}, BaseScore: {basescore} -> {isSafe}"
        )
        return output

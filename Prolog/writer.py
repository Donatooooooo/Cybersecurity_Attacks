import random

#cambiare kbA.pl e decidere se va bene questo alg.

def protocolCombination():
    protocols = ['TCP', 'UDP', 'ICMP']
    trafficTypes = ['HTTP', 'DNS', 'FTP']
    types = ['Malware', 'DDoS', 'Intrusion']
    
    protocol = random.choice(protocols)
    traffic_type = random.choice(trafficTypes)
    type = random.choice(types)
    return (protocol, traffic_type, type)
 
def actionTakenCombination():
    signatures = ['Control', 'Data']
    actionsTaken = ['Logged', 'Blocked', 'Ignored']

    signature = random.choice(signatures)
    action_taken = random.choice(actionsTaken)
    return (signature, action_taken)

def isValid(combinations, tuple):
    if tuple in combinations:
        return False
    return True

def stopWalk(combinations, max):
    if(len(combinations) != max):
        return True
    return False

def computeCombinations():
    protocolCombinations = []
    actionTakenCombinations = []

    while stopWalk(protocolCombinations, 27): #27 sono le combinazioni lecite
        tuple = protocolCombination()
        if isValid(protocolCombinations, tuple):
            protocolCombinations.append(tuple)

    while stopWalk(actionTakenCombinations, 6): #6 sono le combinazioni lecite
        tuple = actionTakenCombination()
        if isValid(actionTakenCombinations, tuple):
            actionTakenCombinations.append(tuple)

    protocolCombinations.sort()
    actionTakenCombinations.sort()
    return protocolCombinations, actionTakenCombinations

def writePrologFact():
    protocols, actions = computeCombinations()

    with open('Prolog/kbA.pl', 'w') as file:
        for item in protocols:
            file.write("protocols_involved" + str(item) + "." + "\n")
        file.write("\n")
        for item in actions:
            file.write("action_taken" + str(item) + "." + "\n")
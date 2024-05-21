from pyswip import Prolog
import csv

prolog = Prolog()

unique_data_protocols = set()
unique_data_action = set()

with open('Dataset/cybersecurity_attacks.csv', 'r') as csv_file:
    csv_reader = csv.DictReader(csv_file)

    for row in csv_reader:
        data_tuple_protocols = (row['Protocol'], row['Traffic Type'], row['Attack Type'])
        data_tuple_action = (row['Packet Type'], row['Action Taken'])
        unique_data_protocols.add(data_tuple_protocols)
        unique_data_action.add(data_tuple_action)


with open('Prolog/protocols_involved.pl', 'w') as pl_file:
    for data in unique_data_protocols:
        pl_file.write(f"protocols_involved('{data[0]}', '{data[1]}', '{data[2]}').\n")

with open('Prolog/action_taken.pl', 'w') as pl_file:
    for data in unique_data_action:
        pl_file.write(f"action_taken('{data[0]}', '{data[1]}').\n")

def action_score(action):
    scores = {
        'Logged': 1,
        'Blocked': 0,
        'Ignored': 2
    }
    return scores.get(action, 0)

def packet_type_score(action):
    scores = {
    'Control': 0,
    'Data': 1
    }
    return scores.get(action, 0)

def protocol_score(action):
    scores = {
        'ICMP': 1,
        'TCP': 0,
        'UDP': 2
    }
    return scores.get(action, 0)

def traffic_score(action):
    scores = {
        'DNS': 0,
        'FTP': 0,
        'HTTP': 1
    }
    return scores.get(action, 0)

def attack_score(action):
    scores = {
        'DDoS': 2,
        'Intrusion': 2,
        'Malware': 2
    }
    return scores.get(action, 0)

with open('Prolog/score.pl', 'w') as pl_file:
    for action in set(action for _, action in unique_data_action):
        score_action = action_score(action)
        pl_file.write(f"action_score('{action}', {score_action}).\n")
    for type in set(type for type, _ in unique_data_action):
        score_type = packet_type_score(type)
        pl_file.write(f"packet_type_score('{type}', {score_type}).\n")
    for protocol in set(protocol for protocol, _, _ in unique_data_protocols):
        score_protocol = protocol_score(protocol)
        pl_file.write(f"protocol_score('{protocol}', {score_protocol}).\n")
    for traffic in set(traffic for _, traffic, _ in unique_data_protocols):
        score_traffic = traffic_score(traffic)
        pl_file.write(f"traffic_score('{traffic}', {score_traffic}).\n")
    for attack in set(attack for _, _, attack in unique_data_protocols):
        score_attack = attack_score(attack)
        pl_file.write(f"attack_score('{attack}', {score_attack}).\n")
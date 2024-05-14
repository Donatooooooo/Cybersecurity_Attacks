:-consult('kb.pl').

protocol_value('TCP',1).
protocol_value('UDP',3).
protocol_value('ICMP',0).
traffic_value('HTTP',2).
traffic_value('DNS',0).
traffic_value('FTP',1).
packet_value('Control',1).
packet_value('Data',3).
attackType_value('Malware',3).
attackType_value('DDoS',3).
attackType_value('Intrusion',3).
actionTaken_value('Logged',0).
actionTaken_value('Blocked',1).
actionTaken_value('Ignored',3).


calculate_severity_score(Protocol,Traffic,Packet,Malware_indicators,Anomaly_Scores,Alerts_Warnings,AttackType,ActionTaken,Firewall_Logs,Alerts,Log_Source
) :-
    protocol_value(Protocol,N1),
    traffic_value(Traffic,N2),
    packet_value(Packet,N3),
    attackType_value(AttackType,N4),
    actionTaken_value(ActionTaken,N5),
    Severity is N1 * 2 + N2 * 2 + N3 + N4 + N5 * 2 + Malware_indicators + Anomaly_Scores + Alerts_Warnings + Firewall_Logs + Alerts + Log_Source,
    write(Severity).
    


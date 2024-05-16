protocols_involved('ICMP', 'DNS', 'DDoS', 1).
protocols_involved('ICMP', 'DNS', 'Intrusion', 1).
protocols_involved('ICMP', 'DNS', 'Malware', 1).
protocols_involved('ICMP', 'FTP', 'DDoS', 2).
protocols_involved('ICMP', 'FTP', 'Intrusion', 2).
protocols_involved('ICMP', 'FTP', 'Malware', 2).
protocols_involved('ICMP', 'HTTP', 'DDoS', 1).
protocols_involved('ICMP', 'HTTP', 'Intrusion', 1).
protocols_involved('ICMP', 'HTTP', 'Malware', 1).
protocols_involved('TCP', 'DNS', 'DDoS', 3).
protocols_involved('TCP', 'DNS', 'Intrusion', 3).
protocols_involved('TCP', 'DNS', 'Malware', 3).
protocols_involved('TCP', 'FTP', 'DDoS', 3).
protocols_involved('TCP', 'FTP', 'Intrusion', 3).
protocols_involved('TCP', 'FTP', 'Malware', 3).
protocols_involved('TCP', 'HTTP', 'DDoS', 3).
protocols_involved('TCP', 'HTTP', 'Intrusion', 3).
protocols_involved('TCP', 'HTTP', 'Malware', 3).
protocols_involved('UDP', 'DNS', 'DDoS', 4).
protocols_involved('UDP', 'DNS', 'Intrusion', 4).
protocols_involved('UDP', 'DNS', 'Malware', 4).
protocols_involved('UDP', 'FTP', 'DDoS',5).
protocols_involved('UDP', 'FTP', 'Intrusion',5).
protocols_involved('UDP', 'FTP', 'Malware',5).
protocols_involved('UDP', 'HTTP', 'DDoS',5).
protocols_involved('UDP', 'HTTP', 'Intrusion',5).
protocols_involved('UDP', 'HTTP', 'Malware',5).

action_taken('Control', 'Blocked', 0).
action_taken('Control', 'Ignored', 2).
action_taken('Control', 'Logged', 1).
action_taken('Data', 'Blocked', 1).
action_taken('Data', 'Ignored', 3).
action_taken('Data', 'Logged', 2).

label(Severity, LABEL) :-
    Severity < 4.0,
    LABEL = low.

label(Severity, LABEL) :-
    Severity = 4.0,
    LABEL = medium.

label_severity(Severity, LABEL) :-
    Severity > 4.0,
    LABEL = high.

network_event_score(Protocol, Packet_Type, Traffic_Type, Malware_Indicators, _,
                        Alerts_Warnings, Attack_Type, Action_Taken, Proxy, _, IDS_Alerts, LABEL) :-
    protocols_involved(P, TT, AT, V1), P=Protocol, TT=Traffic_Type, AT=Attack_Type,
    action_taken(PT, AcT, V2), PT=Packet_Type, AcT=Action_Taken, 
    Severity is V1 + V2 + Proxy - (Alerts_Warnings + Malware_Indicators + IDS_Alerts),
    label_severity(Severity, LABEL).
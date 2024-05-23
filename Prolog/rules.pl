:- consult('kb.pl').

access_complexity_score('high', 0.35).
access_complexity_score('medium', 0.61).
access_complexity_score('low', 0.71).

authentication_score('multiple', 0.45).
authentication_score('single', 0.56).
authentication_score('none', 0.704).

%tutte le vulnerabilità provvengono dalla rete, nessun accesso fisico ai dispositivi 
%QUESTO COMMENTO VA RIMOSSO
access_vector('network', 1).
avail_impact('none', 0).

confinteg_impact('none', 0).
confinteg_impact('partial', 0.275).
confinteg_impact('complete', 0.660).

ac_score(Protocol, Attack_Type, Packet_Type, Firewall, IDS_Alerts, Malware, AC) :-
    access_complexity(P, A, Pt, F, AL, M, VALUE), 
    P=Protocol, A=Attack_Type, Pt=Packet_Type, F=Firewall, AL=IDS_Alerts, M=Malware,
    (
        VALUE < 4.5 -> LABEL = low;
        VALUE < 6 -> LABEL = medium;
        LABEL = high
    ),
    access_complexity_score(LABEL, AC).

au_score(Proxy, Attack_Type, Traffic_Type, Os, AU) :-
    authentication(P, A, T, O, VALUE), 
    P=Proxy, A=Attack_Type, T=Traffic_Type, O=Os,
    (
        VALUE < 4.5 -> LABEL = none;
        VALUE < 6.5 -> LABEL = single;
        LABEL = multiple
    ),
    authentication_score(LABEL, AU).

conf_score(Packet_Type, Traffic_Type, Packet_Length, C) :-
    confidential_impact(P, T, PL, VALUE), 
    P=Packet_Type, T=Traffic_Type, PL=Packet_Length,
    (
        VALUE < 2 -> LABEL = none;
        VALUE < 2.75 -> LABEL = partial;
        LABEL = complete
    ),
    confinteg_impact(LABEL, C).

integ_score(Packet_Type, Protocol, I) :-
    integrity_impact(Pt, P, VALUE), 
    Pt=Packet_Type, P=Protocol,
    (
        VALUE < 1.2 -> LABEL = none;
        VALUE < 2 -> LABEL = partial;
        LABEL = complete
    ),
    confinteg_impact(LABEL, I).

impact(PT, TT, PL, P, IMPACT) :-
    conf_score(PT, TT, PL, C),
    integ_score(PT, P, I),
    avail_impact('none', A),
    IMPACT is 10.41 * (1 - (1 - C) * (1 - I) * (1 - A)).

exploitability(P, AT, PT, F, A, M, PR, TT, OS, EXPLOIT) :-
    ac_score(P, AT, PT, F, A, M, AC),
    au_score(PR, AT, TT, OS, AU),
    access_vector('network', AV),
    EXPLOIT is 20 * AC * AU * AV.

basescore(Packet_Type, Traffic_Type, Packet_Length, Protocol, Attack_Type, 
            Firewall, IDS_Alerts, Malware, Proxy, Os, BASESCORE) :-

    impact(PT, TT, PL, P, IMPACT),
    PT=Packet_Type, TT=Traffic_Type, PL=Packet_Length, P=Protocol,

    exploitability(P, AT, PT, F, A, M, PR, TT, OS, EXPLOIT),
    P=Protocol, AT=Attack_Type, PT=Packet_Type, F=Firewall, A=IDS_Alerts,
    M=Malware, PR=Proxy, TT=Traffic_Type, OS=Os,

    (
        IMPACT = 0 -> F_IMPACT = 0;
        F_IMPACT = 1.176
    ),

    BASESCORE is (0.6 * IMPACT + 0.4 * EXPLOIT - 1.5) * F_IMPACT.

% TESTING 
% ac_score('UDP', 'Intrusion', 'Data', 'Log Data', 'None', 'None', AC).
% au_score('None', 'DDoS', 'DNS', 'Android', AU).
% conf_score('Data', 'DNS', 'Long', C).
% integ_score('Data', 'TCP', I).

% basescore('Data', 'FTP', 'Long', 'UDP', 'Malware', 'Log Data', 'None', 'None', 'Proxy', 'Windows', B).
% basescore('Data', 'FTP', 'Long', 'TCP', 'Intrusion', 'Log Data', 'None', 'None', 'Proxy', 'Mac OS', B).
% basescore('Data', 'HTTP', 'Long', 'TCP', 'Intrusion', 'Log Data', 'None', 'None', 'Proxy', 'Linux', B).
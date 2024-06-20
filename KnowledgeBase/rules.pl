ac_score(Protocol, Attack_Type, Packet_Type, Firewall, IDS_Alerts, Malware, AC) :-
    access_complexity(P, A, Pt, F, AL, M, VALUE), 
    P=Protocol, A=Attack_Type, Pt=Packet_Type, F=Firewall, AL=IDS_Alerts, M=Malware,
    (
        VALUE < 0.47 -> LABEL = low;
        VALUE < 0.67 -> LABEL = medium;
        LABEL = high
    ),
    prop(LABEL, accessComplexity, AC).

au_score(Proxy, Attack_Type, Traffic_Type, Os, AU) :-
    authentication(P, A, T, O, VALUE), 
    P=Proxy, A=Attack_Type, T=Traffic_Type, O=Os,
    (
        VALUE < 0.55 -> LABEL = none;
        VALUE < 0.75 -> LABEL = single;
        LABEL = multiple
    ),
    prop(LABEL, authentication, AU).

conf_score(Packet_Type, Traffic_Type, Packet_Length, C) :-
    confidential_impact(P, T, PL, VALUE), 
    P=Packet_Type, T=Traffic_Type, PL=Packet_Length,
    (
        VALUE < 0.20 -> LABEL = none;
        VALUE < 0.35 -> LABEL = partial;
        LABEL = complete
    ),
    prop(LABEL, confImpact, C).

integ_score(Packet_Type, Protocol, I) :-
    integrity_impact(Pt, P, VALUE), 
    Pt=Packet_Type, P=Protocol,
    (
        VALUE < 0.1 -> LABEL = none;
        VALUE < 0.2 -> LABEL = partial;
        LABEL = complete
    ),
    prop(LABEL, integImpact, I).

impact(PT, TT, PL, P, IMPACT) :-
    conf_score(PT, TT, PL, C),
    integ_score(PT, P, I),
    prop(_, availImpact, A),
    IMPACT is 10.41 * (1 - (1 - C) * (1 - I) * (1 - A)).

exploitability(P, AT, PT, F, A, M, PR, TT, OS, EXPLOIT) :-
    ac_score(P, AT, PT, F, A, M, AC),
    au_score(PR, AT, TT, OS, AU),
    prop(_, accessVector, AV),
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

is_safe(Basescore, AnomalyScore) :-
    network_event('Ignored', Basescore, AnomalyScore),
    Basescore < 3.9,
    AnomalyScore < 50.

is_safe(Basescore, AnomalyScore) :-
    network_event('Logged', Basescore, AnomalyScore),
    Basescore < 6.9,
    AnomalyScore < 60.

is_safe(Basescore, AnomalyScore) :-
    network_event('Blocked', Basescore, AnomalyScore),
    Basescore < 8.9,
    AnomalyScore < 80.

safe_event(Packet_Type, Traffic_Type, Packet_Length, Protocol, Attack_Type, 
            Firewall, IDS_Alerts, Malware, Proxy, Os, AnomalyScore) :-

            basescore(Packet_Type, Traffic_Type, Packet_Length, Protocol, Attack_Type, 
            Firewall, IDS_Alerts, Malware, Proxy, Os, BASESCORE),
            is_safe(BASESCORE, AnomalyScore).

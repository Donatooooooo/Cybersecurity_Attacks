:- consult('aggregations.pl').
:- consult('evaluations.pl').
:- consult('rules.pl').

prop('high', accessComplexity, 0.35).
prop('medium', accessComplexity, 0.61).
prop('low', accessComplexity, 0.71).

prop('multiple', authentication, 0.45).
prop('single', authentication, 0.56).
prop('none', authentication, 0.704).

prop('network', accessVector, 1).
prop('none', availImpact, 0).

prop('none', confImpact, 0).
prop('partial', confImpact, 0.275).
prop('complete', confImpact, 0.660).

prop('none', integImpact, 0).
prop('partial', integImpact, 0.275).
prop('complete', integImpact, 0.660).
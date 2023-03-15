"""
Command line example of using the policy analyzer
Usage:
    python3 analyze.py <file>
    例如：python3 analyze_firewall_rule.py examples/policies_1.csv
"""
import csv
import sys
import os
from io import StringIO
import pandas as pd
from policyanalyzer import Policy, PolicyAnalyzer

EXAMPE_RULES = """protocol,src,s_port,dst,d_port,action
tcp,140.192.37.20,any,0.0.0.0/0,80,deny
tcp,140.192.37.0/24,any,0.0.0.0/0,80,accept
tcp,0.0.0.0/0,any,161.120.33.40,80,accept
tcp,140.192.37.0/24,any,161.120.33.40,80,deny
tcp,140.192.37.30,any,0.0.0.0/0,21,deny
tcp,140.192.37.0/24,any,0.0.0.0/0,21,accept
tcp,140.192.37.0/24,any,161.120.33.40,21,accept
tcp,0.0.0.0/0,any,0.0.0.0/0,any,deny
udp,140.192.37.0/24,any,161.120.33.40,53,accept
udp,0.0.0.0/0,any,161.120.33.40,53,accept
udp,140.192.38.0/24,any,161.120.35.0/24,any,accept
udp,0.0.0.0/0,any,0.0.0.0/0,any,deny"""


DEF_GEN = """A rule (Y) is a generalization of a preceding rule (X) if they
have different actions, and if rule (Y) can match all the packets that
match rule (X)."""

DEF_RXD = """A rule (X) is redundant if it performs the same action on the
same packets as a following rule (Y), and if rule (Y) can match all the packets
that match rule (X), except when there is an intermidate rule (Z)
that relates to (X) but with different action."""

DEF_RYD = """A rule (Y) is redundant if it performs the same action on the
same packets as a preceding rule (X), and if rule (X) can match all the packets
that match rule (Y)."""

DEF_SHD = """A rule (Y) is shadowed by a previous rule (X) if the they have
different actions, and if rule (X) matches all the packets that match rule (Y),
such that the rule (Y) will never be reached."""

DEF_COR = """Two rules (X) and (Y) are correlated if they have different
actions, and rule (X) matches some packets that match rule (Y) and
rule (Y) matches some packets that match rule (X)."""

desc = {
    "GEN": {"short": "Generalization",
            "long": "generalizes",
            "rec": "No change is required.",
            "def": DEF_GEN},
    "SHD": {"short": "Shadowing",
            "long": "is shadowed by",
            "rec": "Move rule Y before X.",
            "def": DEF_SHD},
    "COR": {"short": "Corrolation",
            "long": "corrolates with",
            "rec": "Verify correctness.",
            "def": DEF_COR},
    "RXD": {"short": "Redundancy X",
            "long": "is a superset of",
            "rec": "Remove rule X.",
            "def": DEF_RXD},
    "RYD": {"short": "Redundancy Y",
            "long": "is a subset of",
            "rec": "Remove rule Y",
            "def": DEF_RYD}
}

errors = ['SHD', 'RYD', 'RXD']
warn = ['COR']


def policies_st(policies):
    print("=" * 88)
    print("Policies:")  # 防火墙策略
    for n, p in enumerate(policies):
        print(f"{n:3}: {p}")


def anomalies_st(anomalies):
    print("=" * 88)
    print("Anomalies:")  # 异常情况
    for i in anomalies:
        print(f"{i:3}: {anomalies[i]}")


def to_dict(rel_dict):
    """
    Convert anomalies lists to dictionary
    params：
        rel_dict: 形如{1: [(0, GEN)], 2: [(0, COR)], 3: [(1, SHD), (2, SHD)]}
    """
    my_dict = {}
    for r_item in rel_dict:
        sub_dict = {}
        for i_tuple in rel_dict[r_item]:
            sub_dict[i_tuple[0]] = desc[str(i_tuple[1])]  # i_tuple[1]类型为<enum 'Anomaly'>
        my_dict[r_item] = sub_dict
    return my_dict


def main():
    # 读取命令行参数
    len1 = len(sys.argv)
    if len(sys.argv) > 2:
        out_file_name = sys.argv[2].split('.')[0] + ".csv"
    elif len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as csvfile:
            reader = list(csv.reader(csvfile))[1:]  # 读取包含策略的csv文件，但删除标题
    else:
        print(f"Usage: python3 {os.path.basename(__file__)} <file>")
        sys.exit("Input file name is required!")

        # print("Input file name is required. If it is not provided, the default value is used here")
        # rules_file = StringIO(EXAMPE_RULES)
        # reader = pd.read_csv(rules_file).values.tolist()  # # Create a DataFrame from a csv file

    policies = [Policy(*r) for r in reader]
    policies_st(policies)
    analyzer = PolicyAnalyzer(policies)

    # 找防火墙的相关规则与异常
    rule_relations = analyzer.get_relations()
    anom = analyzer.get_anomalies()  # {1: [(0, GEN)], 2: [(0, COR)], 3: [(1, SHD), (2, SHD)]}
    anomalies_st(anom)

    anom_dict = to_dict(anom)
    print("anom_dict:%s" % anom_dict)
    return anom_dict


if __name__ == "__main__":
    print("Firewall Policy Analyzer".center(88, "*"))
    print("This app analyzes a set of firewall policies and detects any anomalies".center(88, "*"))
    anom_dict = main()
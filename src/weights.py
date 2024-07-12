import sys

# add local directory to system path
sys.path.append("./")
from attack_flow_extension import flow
import argparse
from typing import Any
import pgmpy
from collections import defaultdict
import stix2
import json
from mitreattack.stix20 import MitreAttackData


class TechniquesArray:
    def __init__(self):
        self.techniques = []

    def add_or_increment_technique(self, technique):
        # Check if the technique exists in the array
        for item in self.techniques:
            if item["name"] == technique:
                # If it exists, increment its counter
                item["counter"] += 1
                # print(str(item))
                return

        # If the technique doesn't exist, add it with a counter of 1
        self.techniques.append({"name": technique, "counter": 1})

    def print_techniques(self):
        for item in self.techniques:
            print(f"Technique: {item['name']}, Counter: {item['counter']}")

    def __str__(self):
        return "\n".join(
            [
                f"Technique: {item['name']}, Counter: {item['counter']}"
                for item in self.techniques
            ]
        )

    def get_technique_count(self, technique: str) -> int:
        for item in self.techniques:
            if item["name"] == technique:
                return item["counter"]
        return 0  # Technique not found

    def get_technique(self, technique: str) -> dict:
        for item in self.techniques:
            if item["name"] == technique:
                return item
        return {}  # Technique not found


# Example usage
mitre_data = MitreAttackData("enterprise-attack.json")


all_techniques = mitre_data.get_techniques()
# x = mitre_data.get_attack_id()
# print(x)
techCount = 0
for tech in all_techniques:
    techCount += 1
print(techCount)

tech_array = TechniquesArray()
campaigns = mitre_data.get_all_techniques_used_by_all_campaigns()
print(mitre_data)

camCounter = 0

for campaign in campaigns.keys():
    camCounter += 1
    attack_pattern = mitre_data.get_techniques_used_by_campaign(campaign)
    for pattern in attack_pattern:
        name = pattern.get("object").get("name")
        id = pattern.get("object").get("external_references")[0].get("external_id")
        tech_array.add_or_increment_technique(id)

print(tech_array)
tech_array_w_prob = {}
techCounter = 0
for i in all_techniques:
    name = i.get("name")
    for ref in i["external_references"]:
        if "external_id" in ref:
            id = ref["external_id"]
            count = tech_array.get_technique_count(id)
            prob = count / camCounter
            attackPattern = mitre_data.get_object_by_attack_id(id, "attack-pattern")
            stixID = attackPattern.get("id")
            tech_array_w_prob[techCounter] = {
                "Name": name,
                "ID": id,
                "Count": count,
                "Probability": prob,
                "STIX ID": stixID,
            }
    techCounter += 1
print(tech_array_w_prob)

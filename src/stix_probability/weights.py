from dataclasses import dataclass
from typing import NewType, List
from mitreattack.stix20 import MitreAttackData
from stix2 import ExternalReference, Campaign
from stix2.v20.sdo import AttackPattern

StixId = NewType("StixId", str)


@dataclass
class TechniqueProbability:
    """
    Represents the probability of a technique being used in an attack.

    Attributes:
        name (str): The name of the technique.
        ttp (str): The tactic, technique, and procedure (TTP) associated with the technique.
        count (int): The number of times the technique has been observed.
        probability (float): The probability of the technique being used.
        stix_id (StixId): The STIX identifier for the technique.
    """

    name: str
    ttp: str
    count: int
    probability: float
    stix_id: StixId


class ProbabilityDatabase:
    """
    Represents a probability database that calculates the probabilities of each technique based on the provided STIX data.
    """

    attack_stix_bundle: MitreAttackData
    probability_mapping: dict[StixId, TechniqueProbability]

    def __init__(self, attack_stix_bundle: MitreAttackData):
        self.attack_stix_bundle = attack_stix_bundle
        self._probabilities_from_stix_data()

    def _probabilities_from_stix_data(self):
        """
        Calculate the probabilities of each technique based on the provided STIX data.

        Args:
            mitre_data (MitreAttackData): The STIX data containing information about MITRE ATT&CK techniques and campaigns.

        Returns:
            dict[StixId, TechniqueProbability]: A dictionary mapping each technique's STIX ID to its corresponding TechniqueProbability object.

        """
        techniques: dict[StixId, TechniqueProbability] = {}
        # Using the following method, we can go through each attack pattern and find campaigns where it is referenced
        campaign_by_pattern: dict[StixId, List[Campaign]] = (
            self.attack_stix_bundle.get_all_campaigns_using_all_techniques()
        )
        total_campaigns = len(self.attack_stix_bundle.get_campaigns())
        attack_pattern: StixId
        for attack_pattern in campaign_by_pattern:
            campaign_list: List[Campaign] = campaign_by_pattern[attack_pattern]
            pattern = self.attack_stix_bundle.get_object_by_stix_id(attack_pattern)
            if not isinstance(pattern, AttackPattern):
                raise TypeError(
                    "Expected AttackPattern, got "
                    + str(type(pattern))
                    + " when looking up "
                    + attack_pattern
                )
            external_references: List[ExternalReference] = pattern[
                "external_references"
            ]
            # external references map this stix object to various databases such as ATT&CK and CAPEC. We only care about ATT&CK for now
            for reference in external_references:
                if reference["source_name"] == "mitre-attack":
                    probability = len(campaign_list) / total_campaigns
                    technique_with_prob = TechniqueProbability(
                        pattern["name"],
                        reference["external_id"],
                        len(campaign_list),
                        probability,
                        attack_pattern,
                    )
                    techniques[attack_pattern] = technique_with_prob
                else:
                    pass  # ignoring capec, etc.
        self.probability_mapping = techniques

    def get_probability_for_technique(self, technique_id: StixId) -> float:
        """
        Get the probability of a technique being used in an attack.

        Args:
            technique_id (StixId): The STIX identifier of the technique.

        Returns:
            float: The probability of the technique being used in an attack.
        """
        if technique_id not in self.probability_mapping:
            # uh oh, this means this technique was not found in a campaign, just fudge it and say its super unlikely
            return 0.01
        # maybe one day...
        # raise ValueError(f"Technique {technique_id} not found in the database.")
        return self.probability_mapping[technique_id].probability


# Example usage
# mitre_data = MitreAttackData("enterprise-attack.json")
# print(probabilities_from_stix_data(mitre_data))


"""
some proof that not all techniques are listed in a campaign or group:
flow_bundle = main.read_flow_file("Cobalt Kitty Campaign.json")
flows = flow.get_flows_from_stix_bundle(flow_bundle)
my_flow = flows[0]
attack_data = MitreAttackData('enterprise-attack.json')
probabilities = weights.ProbabilityDatabase(attack_data)
for technique in attack_data.get_techniques():
    #print(list(technique.keys()))
    #print(technique['external_references'])
    pass
print(len(attack_data.get_techniques()))
for campaign in attack_data.get_campaigns():
    #print(list(campaign.keys()))
    pass
technique_by_group = attack_data.get_all_techniques_used_by_all_groups()

all_techniques = []
for group in technique_by_group:
    #print(group)
    for technique in technique_by_group[group]:
        #print(technique['object'].id)
        #print(type(technique['object']))
        all_techniques.append(technique['object'].id)
        pass
technique_by_campaign = attack_data.get_all_techniques_used_by_all_campaigns()
for campaign in technique_by_campaign:
    for technique in technique_by_campaign[campaign]:
        all_techniques.append(technique['object'].id)
        pass
len(list(set(all_techniques)))
"""

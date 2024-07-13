from dataclasses import dataclass
from typing import NewType, List
from mitreattack.stix20 import MitreAttackData
from stix2 import AttackPattern, ExternalReference, Campaign

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


def probabilities_from_stix_data(
    mitre_data: MitreAttackData,
) -> dict[StixId, TechniqueProbability]:
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
        mitre_data.get_all_campaigns_using_all_techniques()
    )
    total_campaigns = len(mitre_data.get_campaigns())
    attack_pattern: StixId
    for attack_pattern in campaign_by_pattern:
        campaign_list: List[Campaign] = campaign_by_pattern[attack_pattern]
        pattern: AttackPattern = mitre_data.get_object_by_stix_id(attack_pattern)
        external_references: List[ExternalReference] = pattern["external_references"]
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
    return techniques


# Example usage
# mitre_data = MitreAttackData("enterprise-attack.json")
# print(probabilities_from_stix_data(mitre_data))

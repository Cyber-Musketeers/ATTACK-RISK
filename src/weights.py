from mitreattack.stix20 import MitreAttackData


class BayesianWeights:
    def __init__(self, mitre_data: MitreAttackData):
        self.techniques = []
        self.mitre_data = mitre_data
        campaigns = mitre_data.get_all_techniques_used_by_all_campaigns()
        self.number_of_campaigns = len(campaigns)

        for campaign in campaigns:
            attack_patterns = mitre_data.get_techniques_used_by_campaign(campaign)
            for pattern in attack_patterns:
                name = pattern.get("object").get("name")
                stix_identifier = (
                    pattern.get("object")
                    .get("external_references")[0]
                    .get("external_id")
                )
                self.add_or_increment_technique(stix_identifier)
        self.techniques_with_probability = {}
        techCounter = 0
        for i in all_techniques:
            name = i.get("name")
            for ref in i["external_references"]:
                if "external_id" in ref:
                    external_id = ref["external_id"]
                    count = self.get_technique_count(id)
                    prob = count / self.number_of_campaigns
                    attack_pattern = mitre_data.get_object_by_attack_id(
                        external_id, "attack-pattern"
                    )
                    stixID = attack_pattern.get("id")
                    self.techniques_with_probability[techCounter] = {
                        "Name": name,
                        "ID": external_id,
                        "Count": count,
                        "Probability": prob,
                        "STIX ID": stixID,
                    }
            techCounter += 1

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

    def get_technique_count(self, technique: str) -> int | None:
        for item in self.techniques:
            if item["name"] == technique:
                return item["counter"]
        return None  # Technique not found

    def get_technique(self, technique: str) -> dict | None:
        for item in self.techniques:
            if item["name"] == technique:
                return item
        return None  # Technique not found


# Example usage
mitre_data = MitreAttackData("enterprise-attack.json")


all_techniques = mitre_data.get_techniques()

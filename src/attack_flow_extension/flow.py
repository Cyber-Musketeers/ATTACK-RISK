from stix2 import Bundle, CustomObject
from stix2.properties import (
    EnumProperty,
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
)
from stix2.v21 import _STIXBase21
from typing import List


@CustomObject(
    "attack-flow",
    [
        ("type", StringProperty(required=True, fixed="attack-flow")),
        ("spec_version", StringProperty(required=True, fixed="2.1")),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("scope", StringProperty(required=True)),
        (
            "start_refs",
            ListProperty(
                ReferenceProperty(valid_types=["attack-action", "attack-condition"]),
                required=True,
            ),
        ),
    ],
)
class AttackFlow(_STIXBase21):
    """
    Represents an attack flow.

    Attributes:
        start_refs (list): A list of start references.

    Methods:
        get_starting_points: Returns the start references of the flow.
    """

    def get_starting_points(self) -> List[str]:
        """
        Returns the start references of the flow.

        Returns:
            list: A list of start references.
        """
        return self.start_refs


@CustomObject(
    "attack-action",
    [
        ("type", StringProperty(required=True, fixed="attack-action")),
        ("spec_version", StringProperty(required=True, fixed="2.1")),
        ("name", StringProperty(required=True)),
        ("tactic_id", StringProperty()),
        ("tactic_ref", ReferenceProperty(valid_types=["x-mitre-tactic"])),
        ("technique_id", StringProperty()),
        ("technique_ref", ReferenceProperty(valid_types=["attack-pattern"])),
        ("description", StringProperty()),
        ("execution_start", TimestampProperty()),
        ("execution_end", TimestampProperty()),
        ("command_ref", ReferenceProperty(valid_types=["process"])),
        ("asset_refs", ListProperty(ReferenceProperty(valid_types=["attack-asset"]))),
        (
            "effect_refs",
            ListProperty(
                ReferenceProperty(
                    valid_types=["attack-action", "attack-operator", "attack-condition"]
                )
            ),
        ),
    ],
)
class AttackAction(_STIXBase21):
    """
    Represents an attack action.

    Attributes:
        technique_ref (str): The technique reference of the action.
        effect_refs (list): A list of effect references of the action.
    """

    def get_technique_ref(self) -> str | None:
        """
        Returns the technique reference of the action.

        Returns:
            str: The technique reference.
        """
        # test if the instance has a technique_ref attribute
        if not hasattr(self, "technique_ref"):
            return None
        return self.technique_ref

    def get_effect_refs(self) -> List[str]:
        """
        Returns the effect references of the action.

        Returns:
            list: A list of effect references.
        """
        return self.effect_refs

    def get_effect_actions(self) -> List[str]:
        """
        Returns the effect actions of the action.

        Returns:
            list: A list of effect actions.
        """
        return [effect for effect in self.effect_refs if effect.type == "attack-action"]

    def get_effect_operators(self) -> List[str]:
        """
        Returns the effect operators of the action.

        Returns:
            list: A list of effect operators.
        """
        return [
            effect for effect in self.effect_refs if effect.type == "attack-operator"
        ]

    def get_effect_conditions(self) -> List[str]:
        """
        Returns the effect conditions of the action.

        Returns:
            list: A list of effect conditions.
        """
        return [
            effect for effect in self.effect_refs if effect.type == "attack-condition"
        ]

    def get_attack_pattern_id(self) -> str | None:
        """
        Returns the attack pattern of the action.

        Returns:
            str: The attack pattern.
        """
        return self.get_technique_ref()


@CustomObject(
    "attack-asset",
    [
        ("type", StringProperty(required=True, fixed="attack-asset")),
        ("spec_version", StringProperty(required=True, fixed="2.1")),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        (
            "object_ref",
            ReferenceProperty(invalid_types=[]),
        ),  # Allow any STIX object reference
    ],
)
class AttackAsset(_STIXBase21):
    """
    Represents an asset involved in an attack.

    This class provides a base class for representing assets in the context of an attack.

    Attributes:
        None

    Methods:
        None
    """

    pass


@CustomObject(
    "attack-condition",
    [
        ("type", StringProperty(required=True, fixed="attack-condition")),
        ("spec_version", StringProperty(required=True, fixed="2.1")),
        ("description", StringProperty(required=True)),
        ("pattern", StringProperty()),
        ("pattern_type", StringProperty()),
        ("pattern_version", StringProperty()),
        (
            "on_true_refs",
            ListProperty(
                ReferenceProperty(
                    valid_types=["attack-action", "attack-operator", "attack-condition"]
                )
            ),
        ),
        (
            "on_false_refs",
            ListProperty(
                ReferenceProperty(
                    valid_types=["attack-action", "attack-operator", "attack-condition"]
                )
            ),
        ),
    ],
)
class AttackCondition(_STIXBase21):
    """
    Represents an attack condition in the system.

    This class provides a base class for defining attack conditions in the system.

    Attributes:
        None

    Methods:
        None
    """


@CustomObject(
    "attack-operator",
    [
        ("type", StringProperty(required=True, fixed="attack-operator")),
        ("spec_version", StringProperty(required=True, fixed="2.1")),
        ("operator", EnumProperty(required=True, allowed=["AND", "OR"])),
        (
            "effect_refs",
            ListProperty(
                ReferenceProperty(
                    valid_types=["attack-action", "attack-operator", "attack-condition"]
                )
            ),
        ),
    ],
)
class AttackOperator(_STIXBase21):
    """
    Represents an attack operator.

    This class provides methods to check whether the operator is an AND or OR operator.

    Attributes:
        operator (str): The operator value.

    Methods:
        is_and(): Returns whether the operator is an AND operator.
        is_or(): Returns whether the operator is an OR operator.
    """

    def is_and(self) -> bool:
        """
        Returns whether the operator is an AND operator.

        Returns:
            bool: True if the operator is an AND operator, False otherwise.
        """
        return self.operator == "AND"

    def is_or(self) -> bool:
        """
        Returns whether the operator is an OR operator.

        Returns:
            bool: True if the operator is an OR operator, False otherwise.
        """
        return self.operator == "OR"


def get_flows_from_stix_bundle(bundle: Bundle) -> List[AttackFlow]:
    """
    Get the attack flow object from a STIX bundle.

    Args:
        bundle (Bundle): The STIX bundle.

    Returns:
        AttackFlow: The attack flow object.
    """
    flows: List[AttackFlow] = []
    for obj in bundle.objects:
        if obj.type == "attack-flow":
            flows.append(obj)
    return flows


def get_single_flow_object_by_id(
    flow_id: str, flow_bundle: Bundle
) -> AttackAction | AttackOperator | AttackCondition:
    """
    Retrieves a single flow object by its ID from a given flow bundle.

    Args:
        flow_id (str): The ID of the flow object to retrieve.
        flow_bundle (Bundle): The flow bundle containing the flow objects.

    Returns:
        AttackAction | AttackOperator | AttackCondition: The flow object with the specified ID.

    Raises:
        ValueError: If no object or more than one object with the specified ID is found.
    """
    candidate_objects = flow_bundle.get_obj(flow_id)
    if len(candidate_objects) != 1:
        raise ValueError(
            f"Expected to find exactly one object with id {flow_id}, but found {len(candidate_objects)}, {candidate_objects}"
        )
    return candidate_objects[0]


# TODO add a funciton to look up object from the flow

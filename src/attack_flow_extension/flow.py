from stix2 import CustomObject
from stix2.v21 import _STIXBase21
from stix2.properties import (
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
    EnumProperty,
)


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
    pass


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
    pass


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
    pass


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
    pass

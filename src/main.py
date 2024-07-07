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


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    # parser.add_argument("--hdm_file", type=str, required=False)
    parser.add_argument("--flow_file", type=str, required=True)
    # parser.add_argument("--output_file", type=str, required=True)
    return parser.parse_args()


def read_flow_file(name: str) -> Any:
    """
    Read a flow file and return the data.

    Parameters:
    name (str): The name of the flow file to read.

    Returns:
    bundle (stix2.Bundle): The parsed STIX bundle data.

    """
    with open(name, "r", encoding="utf-8") as file:
        data = json.load(file)
        bundle = stix2.parse(data, allow_custom=True)
        return bundle


def get_weight(obj: flow.AttackAction) -> int:
    """returns the likelihood the flow action occurs"""
    return 0.5


def create_bayesian_network(attack_flow: Any) -> pgmpy.models.BayesianModel:
    starting_points = attack_flow.start_refs
    starting_objects = []

    # Function to get object by ID
    def get_object_by_id(obj_id):
        return next((obj for obj in attack_flow.objects if obj.id == obj_id), None)

    for starting_point in starting_points:
        starting_objects.append(get_object_by_id(starting_point))

    for starting_object in starting_objects:
        get_weight(starting_object)


def main() -> None:
    """
    Main function of the program.
    """
    args = parse_args()
    # print_flow(args.flow_file)
    flow_stix = read_flow_file(args.flow_file)

    bayesian_network = create_bayesian_network(flow_stix)


def print_flow(file: str) -> None:
    # Parse the STIX 2.1 bundle
    with open(file, "r", encoding="utf8") as file:
        bundle = stix2.parse(file.read(), allow_custom=True)

        # Initialize dictionaries to store object counts and relationships
        object_counts = defaultdict(int)
        relationships = defaultdict(list)

        # Analyze the objects in the bundle
        for obj in bundle.objects:
            # Count objects by type
            object_counts[obj.type] += 1

            # Store relationships
            if obj.type == "relationship":
                relationships[obj.source_ref].append(obj.target_ref)

        # Function to get object by ID
        def get_object_by_id(obj_id):
            return next((obj for obj in bundle.objects if obj.id == obj_id), None)

        # Analyze attack flow
        attack_flow = next(obj for obj in bundle.objects if obj.type == "attack-flow")
        print(f"Attack Flow: {attack_flow.name}")
        print(f"Description: {attack_flow.description}")
        print(f"Scope: {attack_flow.scope}")

        # Analyze starting points
        print("\nStarting points:")
        for start_ref in attack_flow.start_refs:
            start_obj = get_object_by_id(start_ref)
            print(f"- {start_obj.name} ({start_obj.technique_id})")

        # Analyze attack actions
        print("\nAttack Actions:")
        for obj in bundle.objects:
            if obj.type == "attack-action":
                print(f"- {obj.name} ({obj.technique_id})")
                if hasattr(obj, "description"):
                    print(f"  Description: {obj.description}")

        # Print object counts
        print("\nObject counts:")
        for obj_type, count in object_counts.items():
            print(f"{obj_type}: {count}")

        # Analyze relationships
        print("\nRelationships:")
        for source_ref, target_refs in relationships.items():
            source_obj = get_object_by_id(source_ref)
            if source_obj:
                print(
                    f"{source_obj.type} '{source_obj.name if hasattr(source_obj, 'name') else source_obj.id}' is related to:"
                )
                for target_ref in target_refs:
                    target_obj = get_object_by_id(target_ref)
                    if target_obj:
                        print(
                            f"  - {target_obj.type} '{target_obj.name if hasattr(target_obj, 'name') else target_obj.id}'"
                        )


if __name__ == "__main__":
    main()

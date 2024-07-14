import sys

# add local directory to system path
sys.path.append("./")
from attack_flow_extension import flow
from stix_probability import weights
import argparse
from typing import Any
from collections import defaultdict
import stix2
import json
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from mitreattack.stix20 import MitreAttackData
import networkx as nx


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--flow_file", type=str, required=True)
    parser.add_argument("--attack_stix", type=str, required=True)
    # parser.add_argument("--output_file", type=str, required=True)
    return parser.parse_args()


def read_flow_file(name: str) -> stix2.Bundle:
    """
    Read a flow file and return the data.

    Parameters:
    name (str): The name of the flow file to read.

    Returns:
    bundle (stix2.Bundle): The parsed STIX bundle data.

    """
    with open(name, "r", encoding="utf-8") as file:
        data = json.load(file)
        bundle: stix2.Bundle = stix2.parse(data, allow_custom=True)
        return bundle


def create_bayesian_network(
    attack_flow: flow.AttackFlow, probabilities: weights.ProbabilityDatabase
) -> BayesianNetwork:
    starting_points = attack_flow.get_statring_points()
    starting_objects = []

    # Initialize the Bayesian Model
    model = BayesianNetwork()
    # passed in weights
    node_weights = {}

    for obj in attack_flow.objects:
        # add object by object to BN
        model.add_node(obj.id)

        # check edges for same attack ref, if same then on same level and
        # if not then just move on and connect to next node
        # probably another for loop to look at remaining objects?
        # if same attack ref...
        #    look at previous nodes and connect to right parent
        # if not then just connect to parent

        # model.add_edge(obj.id, related_obj_id)

        # need logic to check for OR and AND and to just make a node following
        # the creation of the CPD below as a trigger

        # Add weights to nodes - need inputted weights
        cpds = []
        for node, weight in node_weights.items():
            if weight is not None:
                # Assuming binary states for simplicity (0, 1) and the provided weight is the probability of state 1
                cpd = TabularCPD(
                    variable=node, variable_card=2, values=[[1 - weight], [weight]]
                )
                cpds.append(cpd)

        model.add_cpds(*cpds)

        return model

    # Return the Bayesian model and the initialized node weights dictionary
    return model


def convert_attack_flow_to_nx(
    attack_flow: flow.AttackFlow, flow_bundle: stix2.Bundle
) -> nx.DiGraph:
    G = nx.DiGraph()
    queue = []
    for starting_node in attack_flow.get_starting_points():
        backing_obj = flow.get_single_flow_object_by_id(starting_node, flow_bundle)
        G.add_node(starting_node, object=backing_obj)
        queue.append(starting_node)
    while queue:
        node = queue.pop(0)
        list_of_objs = flow_bundle.get_obj(node)
        if len(list_of_objs) != 1:
            raise ValueError("Expected to find exactly one object with id {node}")
        node_obj = list_of_objs[0]
        if "effect_refs" not in node_obj:
            continue
        for child in node_obj["effect_refs"]:
            if child not in queue:
                backing_obj = flow.get_single_flow_object_by_id(child, flow_bundle)
                G.add_node(child, object=backing_obj)
                queue.append(child)
            G.add_edge(node, child)
    return G


def main() -> None:
    """
    Main function of the program.
    """
    args = parse_args()
    # print_flow(args.flow_file)
    flow_bundle: stix2.Bundle = read_flow_file(args.flow_file)
    flows = flow.get_flows_from_stix_bundle(flow_bundle)
    # technically there can be multiple attack flows in a stix bundle but I am too lazy to deal with that
    if len(flows) != 1:
        raise ValueError("Expected exactly one attack flow in the file.")
    attack_data = MitreAttackData(args.attack_stix)
    probability_db = weights.ProbabilityDatabase(attack_data)
    flow_nx = convert_attack_flow_to_nx(flows[0], flow_bundle)

    bayesian_network = flow_nx_to_pgmpy(flow_nx, probability_db)


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

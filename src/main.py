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
import numpy as np


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


def flow_nx_to_pgmpy(
    graph: nx.DiGraph, probabilities: weights.ProbabilityDatabase
) -> BayesianNetwork | None:
    model = BayesianNetwork(graph)

    for node, node_data in model.nodes(data=True):
        parents = list(model.predecessors(node))
        flow_obj = node_data["object"]
        if not parents:
            # isolated node
            if flow_obj.type == "attack-action":
                # why do you just have the one node? this is a lot of work for just 1 node.
                relevant_attack_pattern: str = flow_obj.get_attack_pattern_id()
                probability = probabilities.get_probability_for_technique(
                    weights.StixId(relevant_attack_pattern)
                )
                cpd = TabularCPD(
                    variable=node,
                    variable_card=2,
                    values=[[probability], [1 - probability]],
                )
                model.add_cpds(cpd)
            elif flow_obj.type == "attack-operator":
                # what is going on here? you have a lone attack operator not connected to anything. What does this mean? rethink your life
                cpd = TabularCPD(variable=node, variable_card=2, values=[[0.5], [0.5]])
            elif flow_obj.type == "attack-condition":
                # what is going on here? you have a lone attack condition not connected to anything. What does this mean? rethink your life
                cpd = TabularCPD(variable=node, variable_card=2, values=[[0.5], [0.5]])
            else:
                raise ValueError("Unknown node type")
        elif parents:
            if flow_obj.type == "attack-action":
                evidence_card = []
                relevant_attack_pattern: str = flow_obj.get_attack_pattern_id()
                probability = probabilities.get_probability_for_technique(
                    weights.StixId(relevant_attack_pattern)
                )
                vals = np.zeros((2, 2 ** len(parents)))
                # top row is probability, bottom row is anti-probablity
                vals[0, :] = probability
                vals[1, :] = 1 - probability
                evidence_card = [2] * len(parents)
                cpd = TabularCPD(
                    variable=node,
                    variable_card=2,
                    values=vals,
                    evidence=parents,
                    evidence_card=evidence_card,
                )
                model.add_cpds(cpd)
            elif flow_obj.type == "attack-operator":
                vals = np.zeros((2, 2 ** len(parents)))
                # top row is probability, bottom row is anti-probablity
                evidence_card = [2] * len(parents)
                if flow_obj.is_and():
                    # For AND, True only if all parents are True
                    vals[0, :-1] = 1  # False for all combinations except last
                    vals[0, -1] = 0  # False when all parents are True
                    vals[1, :-1] = 0  # True only for last combination
                    vals[1, -1] = 1  # True when all parents are True
                elif flow_obj.is_or():
                    # For OR, True if any parent is True
                    vals[0, 0] = 1  # False only when all parents are False
                    vals[0, 1:] = 0  # False for all other combinations
                    vals[1, 0] = 0  # True for all combinations except first
                    vals[1, 1:] = 1  # True if any parent is True
                else:
                    raise ValueError("Unknown operator type")
                cpd = TabularCPD(
                    variable=node,
                    variable_card=2,
                    values=vals,
                    evidence=parents,
                    evidence_card=evidence_card,
                )
                model.add_cpds(cpd)
            elif flow_obj.type == "attack-condition":
                # the way the model is setup, the attack condition stuff doesn't really make sense. Placeholder it as a uniform binary thing
                cpd = TabularCPD(variable=node, variable_card=2, values=[[0.5], [0.5]])
            else:
                raise ValueError("Unknown node type")
        if not model.check_model():
            raise ValueError("Model is invalid")
        return model


def convert_attack_flow_to_nx(
    attack_flow: flow.AttackFlow, flow_bundle: stix2.Bundle
) -> nx.DiGraph:
    """
    performs a BFS to convert the attackflow to a networkx graph
    """
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


if __name__ == "__main__":
    main()

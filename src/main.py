"""
This module provides a framework for analyzing cyber attack patterns and probabilities using Bayesian networks.
It integrates various libraries such as NetworkX for graph operations, NumPy for numerical computations, and pgmpy for probabilistic graphical models. The module leverages the MITRE ATT&CK framework through the use of STIX 2.0 data format for expressing and exchanging cyber threat intelligence.

The core functionality includes parsing command line arguments to specify input and output files, reading attack flow files in STIX format, and constructing Bayesian networks to model and infer attack probabilities. It utilizes custom extensions for attack flow and probability weighting to enhance the analysis.

Features:
- Command line interface for specifying input/output files.
- Reading and parsing STIX 2.0 formatted attack flow files.
- Construction and inference in Bayesian networks for attack analysis.

Dependencies:
- networkx
- numpy
- stix2
- mitreattack.stix20
- pgmpy
"""

import sys

# add local directory to system path
sys.path.append("./")
import argparse
import json
from collections import defaultdict
from typing import Any

import networkx as nx
import numpy as np
import stix2
from mitreattack.stix20 import MitreAttackData
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from pgmpy.models import BayesianNetwork

from attack_flow_extension import flow
from stix_probability import weights
from pgmpy.readwrite import NETWriter


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--flow_file", type=str, required=True)
    parser.add_argument("--attack_stix", type=str, required=True)
    parser.add_argument("--output_file", type=str, required=True)
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
) -> BayesianNetwork:
    """
    Converts a NetworkX directed graph representing a flow to a Bayesian network using pgmpy library.

    Args:
        graph (nx.DiGraph): The NetworkX directed graph representing the flow.
        probabilities (weights.ProbabilityDatabase): The probability database containing the ATT&CK probabilities.

    Returns:
        BayesianNetwork: The converted Bayesian network.

    Raises:
        ValueError: If the model is invalid.
    """
    model = BayesianNetwork(graph)
    for node, node_data in model.nodes(data=True):
        parents = list(model.predecessors(node))
        flow_obj = node_data["object"]
        if not parents:
            # isolated node
            if flow_obj.type == "attack-action":
                # why do you just have the one node? this is a lot of work for just 1 node.
                relevant_attack_pattern: str | None = flow_obj.get_attack_pattern_id()
                probability = probabilities.get_probability_for_technique(
                    weights.StixId(relevant_attack_pattern)
                )
                cpd = TabularCPD(
                    variable=node,
                    variable_card=2,
                    values=[[1 - probability], [probability]],
                )
                model.add_cpds(cpd)
            elif flow_obj.type == "attack-operator":
                # what is going on here? you have a lone attack operator not connected to anything. What does this mean? rethink your life
                cpd = TabularCPD(variable=node, variable_card=2, values=[[0.5], [0.5]])
                model.add_cpds(cpd)
            elif flow_obj.type == "attack-condition":
                # what is going on here? you have a lone attack condition not connected to anything. What does this mean? rethink your life
                cpd = TabularCPD(variable=node, variable_card=2, values=[[0.5], [0.5]])
                model.add_cpds(cpd)
            else:
                raise ValueError("Unknown node type")
        elif parents:
            if flow_obj.type == "attack-action":
                evidence_card = []
                relevant_attack_pattern: str | None = flow_obj.get_attack_pattern_id()
                if relevant_attack_pattern is None:
                    probability = probabilities.get_probability_for_technique(
                        weights.StixId("")
                    )
                else:
                    probability = probabilities.get_probability_for_technique(
                        weights.StixId(relevant_attack_pattern)
                    )
                vals = np.zeros((2, 2 ** len(parents)))
                # top row is false, bottom row is true
                vals[0, :] = 1 - probability
                vals[1, :] = probability
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
                vals = np.zeros((2, 2 ** len(parents)))
                probability = 0.5
                # top row is false, bottom row is true
                vals[0, :] = 1 - probability
                vals[1, :] = probability
                evidence_card = [2] * len(parents)
                cpd = TabularCPD(
                    variable=node,
                    variable_card=2,
                    values=vals,
                    evidence=parents,
                    evidence_card=evidence_card,
                )
                model.add_cpds(cpd)
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


def pgmpy_to_unbbayes_hugin(model: BayesianNetwork) -> str:
    """
    Convert a pgmpy BayesianNetwork model to a Hugin format string.

    Parameters:
        model (BayesianNetwork): The pgmpy BayesianNetwork model to convert.

    Returns:
        str: The Hugin format string representation of the model.
    """
    writer = NETWriter(model)
    raw_hugin_file = str(writer)
    # cheap hacks to get around a bug in either pgmpy or unbbayes.
    for line in iter(raw_hugin_file.splitlines()):
        # remove lines with "object" in them because unbbayes doesn't know what to do with that
        if "object" in line:
            raw_hugin_file = raw_hugin_file.replace(line, "")
        # remove lines with "weight" in them because unbbayes doesn't know what to do with that
        elif "weight" in line:
            raw_hugin_file = raw_hugin_file.replace(line, "")
    # At the end of a node declaration, there is a open-squirly bracket. Unbbayes won't read the file unless thats on a new line
    # Also this makes the net file pretty ugly but if it works it works
    # thanks r: https://www.bnlearn.com/bnrepository/discrete-small.html#asia
    raw_hugin_file = raw_hugin_file.replace("{", "\n{")
    return raw_hugin_file


def make_nx_graph_more_readable(graph: nx.DiGraph) -> nx.DiGraph:
    """
    Make the graph more readable by adding labels to the nodes.

    Args:
        graph (nx.DiGraph): The graph to make more readable.

    Returns:
        nx.DiGraph: The more readable graph.
    """
    for node, node_data in graph.nodes(data=True):
        obj = node_data["object"]
        if obj.type == "attack-action":
            graph.nodes[node]["label"] = f'"Action: {obj.name}"'
        elif obj.type == "attack-operator":
            graph.nodes[node]["label"] = f'"Operator: {obj.operator}"'
        elif obj.type == "attack-condition":
            graph.nodes[node]["label"] = f'"Condition: {obj.description}"'
        else:
            raise ValueError("Unknown node type")

    # add positions to the nodes for better visualization, otherwise we will get a cthulhu monster in unbbayes
    positions = nx.spring_layout(graph, k=0.5, iterations=50)
    scale = 500  # 500 is probably fine
    # Find the minimum values
    min_x = min(coord[0] for coord in positions.values())
    min_y = min(coord[1] for coord in positions.values())

    # Shift all positions to be positive
    positions = {
        node: (coord[0] - min_x, coord[1] - min_y) for node, coord in positions.items()
    }

    # Scale up the positions
    positions = {
        node: (coord[0] * scale, coord[1] * scale) for node, coord in positions.items()
    }

    # Round to whole numbers
    positions = {
        node: (round(coord[0]), round(coord[1])) for node, coord in positions.items()
    }
    for node, pos in positions.items():
        graph.nodes[node]["position"] = f"({pos[0]},{pos[1]})"
    return graph


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
    flow_nx = make_nx_graph_more_readable(flow_nx)
    bayesian_network = flow_nx_to_pgmpy(flow_nx, probability_db)

    content = pgmpy_to_unbbayes_hugin(bayesian_network)
    with open(args.output_file, "w", encoding="utf-8") as file:
        file.write(content)
    print("New bayesian network written to", args.output_file)
    print("The network can be loaded into Hugin or Unbbayes")
    print("Thanks for using the program!")


if __name__ == "__main__":
    main()

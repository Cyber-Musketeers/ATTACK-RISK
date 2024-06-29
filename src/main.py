import argparse
from typing import Any
import pgmpy
import stix2
import json


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--hdm_file", type=str, required=True)
    parser.add_argument("--flow_file", type=str)
    parser.add_argument("--output_file", type=str, required=True)
    return parser.parse_args()


def read_flow_file(name) -> Any:
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


def main() -> None:
    """
    Main function of the program.
    """
    args = parse_args()
    data = read_flow_file(args.flow_file)


if __name__ == "__main__":
    main()

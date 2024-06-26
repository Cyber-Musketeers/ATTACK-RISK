import argparse
import pgmpy
import stix2


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


def main():
    """
    Main function of the program.
    """
    args = parse_args()
    print(f"Hello, {args.name}!")


if __name__ == "__main__":
    main()

import unittest
import os
import json
from main import read_flow_file


class TestReadFlowFile(unittest.TestCase):
    def test_read_flow_file(self):
        # Construct the path to the JSON file
        file_path = os.path.join(os.path.dirname(__file__), "attack-flow-example.json")

        # Read and parse the JSON file
        with open(file_path, "r", encoding="utf-8") as file:
            expected_data = json.load(file)

        # Call the function under test
        bundle = read_flow_file(file_path)

        # Assert that the parsed JSON matches the expected data
        self.assertEqual(bundle, expected_data)


if __name__ == "__main__":
    unittest.main()

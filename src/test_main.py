import sys

# add local directory to system path
sys.path.append("./")
import pytest
import networkx as nx
from stix2 import Bundle
from main import convert_attack_flow_to_nx
from attack_flow_extension import flow


# Mock classes and functions
class MockAttackFlow:
    """A class representing a mock attack flow."""

    def get_starting_points(self):
        """Get the starting points of the attack flow.

        Returns:
            list: A list of starting points.
        """
        return ["node1"]


class MockBundle:
    """A class representing a mock bundle."""

    def get_obj(self, node_id):
        """
        Retrieve the object associated with the given node ID.

        Parameters:
            node_id (str): The ID of the node.

        Returns:
            list: The object associated with the node ID, or an empty list if not found.
        """
        mock_objects = {
            "node1": [{"effect_refs": ["node2", "node3"]}],
            "node2": [{"on_true_refs": ["node4"]}],
            "node3": [{}],
            "node4": [{}],
        }
        return mock_objects.get(node_id, [])


def mock_get_single_flow_object_by_id(node_id, bundle):
    """
    Mock function to get a single flow object by its ID.

    Args:
        node_id (int): The ID of the flow object.
        bundle (dict): The bundle containing flow objects.

    Returns:
        dict: The flow object with the specified ID.
    """
    return {"id": node_id}


# Test function
def test_convert_attack_flow_to_nx():
    """
    Test case for the convert_attack_flow_to_nx function.

    This test case verifies that the convert_attack_flow_to_nx function correctly converts
    an attack flow and a bundle into a networkx DiGraph object. It checks the resulting graph's
    nodes, edges, and node attributes.

    """
    # Arrange
    mock_attack_flow = MockAttackFlow()
    mock_bundle = MockBundle()

    # Monkey patch the flow.get_single_flow_object_by_id function
    flow.get_single_flow_object_by_id = mock_get_single_flow_object_by_id

    # Act
    result = convert_attack_flow_to_nx(mock_attack_flow, mock_bundle)

    # Assert
    assert isinstance(result, nx.DiGraph)
    assert len(result.nodes) == 4
    assert len(result.edges) == 3

    # Check nodes
    assert "node1" in result.nodes
    assert "node2" in result.nodes
    assert "node3" in result.nodes
    assert "node4" in result.nodes

    # Check edges
    assert ("node1", "node2") in result.edges
    assert ("node1", "node3") in result.edges
    assert ("node2", "node4") in result.edges

    # Check node attributes
    for node in result.nodes:
        assert "object" in result.nodes[node]
        assert result.nodes[node]["object"] == {"id": node}


# Test for ValueError
def test_convert_attack_flow_to_nx_value_error():
    """
    Test case for the convert_attack_flow_to_nx function when a ValueError is expected.

    This test case checks if the convert_attack_flow_to_nx function raises a ValueError
    when the ErrorBundle's get_obj method returns an empty list. The test expects the
    ValueError message to contain the string "Expected to find exactly one object with id node1".

    Raises:
        AssertionError: If the ValueError is not raised or the error message does not match the expected string.
    """

    class ErrorBundle:
        """Represents a bundle of errors."""

        def get_obj(self, node_id):
            """
            Retrieves the object associated with the given node ID.

            Args:
                node_id (int): The ID of the node.

            Returns:
                list: An empty list to trigger a ValueError.
            """
            return []

    class ErrorBundle:
        def get_obj(self, node_id):
            return []  # Return an empty list to trigger ValueError

    with pytest.raises(
        ValueError, match="Expected to find exactly one object with id node1"
    ):
        convert_attack_flow_to_nx(MockAttackFlow(), ErrorBundle())

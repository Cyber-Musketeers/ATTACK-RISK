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
    def get_starting_points(self):
        return ["node1"]


class MockBundle:
    def get_obj(self, node_id):
        mock_objects = {
            "node1": [{"effect_refs": ["node2", "node3"]}],
            "node2": [{"on_true_refs": ["node4"]}],
            "node3": [{}],
            "node4": [{}],
        }
        return mock_objects.get(node_id, [])


def mock_get_single_flow_object_by_id(node_id, bundle):
    return {"id": node_id}


# Test function
def test_convert_attack_flow_to_nx():
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
    class ErrorBundle:
        def get_obj(self, node_id):
            return []  # Return an empty list to trigger ValueError

    with pytest.raises(
        ValueError, match="Expected to find exactly one object with id node1"
    ):
        convert_attack_flow_to_nx(MockAttackFlow(), ErrorBundle())

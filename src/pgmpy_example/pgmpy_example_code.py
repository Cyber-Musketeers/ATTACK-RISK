from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

# Define the structure of the Bayesian Network
model = BayesianNetwork(
    [
        ("HARMFUL", "CONF_THREATS"),
        ("HARMFUL", "INTEG_THREATS"),
        ("HARMFUL", "AVAIL_THREATS"),
        ("DIFFICULTY", "CONF_THREATS"),
        ("DIFFICULTY", "INTEG_THREATS"),
        ("DIFFICULTY", "AVAIL_THREATS"),
        ("CONF_THREATS", "OCT"),
        ("INTEG_THREATS", "OCI"),
        ("AVAIL_THREATS", "OCA"),
        ("OCT", "SYSTEM_COMPROMISE"),
        ("OCI", "SYSTEM_COMPROMISE"),
        ("OCA", "SYSTEM_COMPROMISE"),
        ("COUNTERMEASURE", "SYSTEM_COMPROMISE"),
    ]
)

# Define the CPDs (example values; you need to replace with actual values)
cpd_harmful = TabularCPD(
    variable="HARMFUL", variable_card=3, values=[[0.3333], [0.3333], [0.3333]]
)
cpd_difficulty = TabularCPD(
    variable="DIFFICULTY", variable_card=3, values=[[0.3333], [0.3333], [0.3333]]
)

cpd_conf_threats = TabularCPD(
    variable="CONF_THREATS",
    variable_card=2,
    values=[
        [0.7387, 0.7387, 0.7387, 0.7387, 0.7387, 0.7387, 0.7387, 0.7387, 0.7387],
        [0.2613, 0.2613, 0.2613, 0.2613, 0.2613, 0.2613, 0.2613, 0.2613, 0.2613],
    ],
    evidence=["HARMFUL", "DIFFICULTY"],
    evidence_card=[3, 3],
)

cpd_integ_threats = TabularCPD(
    variable="INTEG_THREATS",
    variable_card=2,
    values=[
        [0.5589, 0.5589, 0.5589, 0.5589, 0.5589, 0.5589, 0.5589, 0.5589, 0.5589],
        [0.4411, 0.4411, 0.4411, 0.4411, 0.4411, 0.4411, 0.4411, 0.4411, 0.4411],
    ],
    evidence=["HARMFUL", "DIFFICULTY"],
    evidence_card=[3, 3],
)

cpd_avail_threats = TabularCPD(
    variable="AVAIL_THREATS",
    variable_card=2,
    values=[
        [0.6244, 0.6244, 0.6244, 0.6244, 0.6244, 0.6244, 0.6244, 0.6244, 0.6244],
        [0.3756, 0.3756, 0.3756, 0.3756, 0.3756, 0.3756, 0.3756, 0.3756, 0.3756],
    ],
    evidence=["HARMFUL", "DIFFICULTY"],
    evidence_card=[3, 3],
)

cpd_oct = TabularCPD(
    variable="OCT",
    variable_card=2,
    values=[[0.721, 0.721], [0.279, 0.279]],
    evidence=["CONF_THREATS"],
    evidence_card=[2],
)

cpd_oci = TabularCPD(
    variable="OCI",
    variable_card=2,
    values=[[0.2286, 0.2286], [0.7714, 0.7714]],
    evidence=["INTEG_THREATS"],
    evidence_card=[2],
)

cpd_oca = TabularCPD(
    variable="OCA",
    variable_card=2,
    values=[[0.4371, 0.4371], [0.5629, 0.5629]],
    evidence=["AVAIL_THREATS"],
    evidence_card=[2],
)

cpd_countermeasure = TabularCPD(
    variable="COUNTERMEASURE", variable_card=2, values=[[1], [0]]
)

cpd_system_compromise = TabularCPD(
    variable="SYSTEM_COMPROMISE",
    variable_card=2,
    values=[
        [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
        [
            1,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
        ],
    ],
    evidence=["OCT", "OCI", "OCA", "COUNTERMEASURE"],
    evidence_card=[2, 2, 2, 2],
)

# Add CPDs to the model
model.add_cpds(
    cpd_harmful,
    cpd_difficulty,
    cpd_conf_threats,
    cpd_integ_threats,
    cpd_avail_threats,
    cpd_oct,
    cpd_oci,
    cpd_oca,
    cpd_countermeasure,
    cpd_system_compromise,
)

# Validate the model
model.check_model()

# Perform inference
inference = VariableElimination(model)

# Example query
query_result = inference.query(
    variables=["SYSTEM_COMPROMISE"], evidence={"HARMFUL": 1, "DIFFICULTY": 2}
)
print(query_result)

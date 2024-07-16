# ATTACK-RISK
## What is this?

This project is a preliminary attempt at converting the graphs created in [MITRE's ATT&CK Flow](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/our-work/attack-flow/) into a Bayesian network that can be used by [UnBBayes](https://unbbayes.sourceforge.net/). Under the hood it uses STIX2, MITRE ATT&CK, and pgmpy.

## Usage:
### Requirements
- git
- Python 3.11 or higher
- [Poetry](https://python-poetry.org/)


### Step 1: Clone the repository:

`git clone git@github.com:Cyber-Musketeers/ATTACK-RISK.git`


### Step 2: Install dependencies with Poetry

`poetry install`

![poetry_install](https://github.com/user-attachments/assets/b9fffefd-1ba7-4509-8d87-cc0ae9a8daf6)

### Step 3: Run main.py (ATTACK-RISK/src/main.py) with the following arguments:

# Windows: py .\main.py a1 a2 a3
# Linux/Mac: python ./main.py a1 a2 a3

# a1: Attack Flow File
# a2: MITRE ATT&CK Stix File
# a3: Output File

# Step 3: You will receive a complete Bayesian network file (.net) to be used within your program of choice. These programs include Unbbayes, Hugin, etc.

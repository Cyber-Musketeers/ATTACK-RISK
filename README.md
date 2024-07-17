# ATTACK-RISK
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Cyber-Musketeers/ATTACK-RISK/badge)](https://scorecard.dev/viewer/?uri=github.com/Cyber-Musketeers/ATTACK-RISK)
![License](https://img.shields.io/github/license/Cyber-Musketeers/ATTACK-RISK)
![GitHub forks](https://img.shields.io/github/forks/Cyber-Musketeers/ATTACK-RISK)
![GitHub stars](https://img.shields.io/github/stars/Cyber-Musketeers/ATTACK-RISK)
![GitHub contributors](https://img.shields.io/github/contributors/Cyber-Musketeers/ATTACK-RISK)
![GitHub last commit](https://img.shields.io/github/last-commit/Cyber-Musketeers/ATTACK-RISK)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Cyber-Musketeers/ATTACK-RISK)
![GitHub top language](https://img.shields.io/github/languages/top/Cyber-Musketeers/ATTACK-RISK)





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

### Step 3: Export an ATT&CK Flow from the [MITRE Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/ui/)

![MITRE_EXPORT](https://github.com/user-attachments/assets/fd8c8405-5f5c-4e46-8aee-bb8c9cd4020d)

### Step 4: Download a copy of the MITRE ATT&CK STIX Bundle

Windows: `Invoke-Webrequest https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json -outfile enterprise-attack-15.1.json`

Linux: `wget https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json`

Mac: You're on your own

### Step 5: Activate the venv poetry installed

`poetry shell`

### Step 6: Run main.py (ATTACK-RISK/src/main.py) with the following arguments:

`cd src`

`python3 .\main.py --flow_file flow_export.json --attack_stix enterprise-attack-15.1.json --output_file test.net`

![TOOL_RUN](https://github.com/user-attachments/assets/3bdcbff7-6a56-41e7-89e8-21224d6f9840)


## Step 7: Load the output Hugin net file into UnBBayes

![unbbayes_load](https://github.com/user-attachments/assets/50263070-c4c7-4984-848a-f68321222b7c)

## Developing

This repository contains a devcontainer configuration that can be used to develop the application on various platforms.

## Future Work

This implementation has a shaky ground on how the probabilities are calculated, they currently follow the methodology laid out by [1], but this means that over half of the ATT&CK TTPs have "minimal" probability

## Citations

[1] B. Al-Sada, A. Sadighian, and G. Oligeri, “Analysis and Characterization of Cyber Threats Leveraging the MITRE ATT&CK Database,” IEEE Access, vol. 12, pp. 1217–1234, 2024, doi: 10.1109/ACCESS.2023.3344680.


## Troubleshooting

Sometimes pgmpy (and the transient scikit-learn dependencies) can get themselves into an unstable state. If you are running into issues on a old virtual environment, try deactivating the virtual environment, deleting the `.venv` folder, and reinstalling.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Cyber-Musketeers/ATTACK-RISK&type=Date)](https://star-history.com/#Cyber-Musketeers/ATTACK-RISK&Date)

import subprocess
import os

files = [
    "bsp_integrity",
    "bsp_pib_auth",
    "bsp_conf",
    "bsp_replay_flawed",
    "bsp_replay_unique",
    "sdls_auth",
    "sdls_conf",
    "sdls_integrity",
    "sdls_replay"
]

def run_cpsa_pipeline(file):
    scm = f"{file}.scm"
    analysis = f"{file}_analysis.txt"
    shapes = f"{file}_shapes.txt"
    xhtml = f"{file}_models.xhtml"

    print(f"Running CPSA analysis for {scm}...")

    subprocess.run(["cpsa4", "-o", analysis, scm])
    subprocess.run(["cpsa4shapes", "-o", shapes, analysis])
    subprocess.run(["cpsa4graph", "-o", xhtml, shapes])

    print(f"Done: {xhtml}")
    print("-" * 40)


for file in files:
    run_cpsa_pipeline(file)

print("All CPSA analyses complete.")

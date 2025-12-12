import subprocess
import os

files = [
    "bsp_integrity",
    "bsp_pib_auth",
    "bsp_conf",
    "bsp_replay_pcb",
    "bsp_replay_bab",
    "bsp_replay_pib",
    "bsp_replay_pcb_sdls_approach",
    "bsp_replay_pib_sdls_approach",
    "bsp_replay_bab_sdls_approach",
    "sdls_auth",
    "sdls_conf",
    "sdls_integrity",
    "sdls_replay_aead",
    "sdls_replay_auth_only"
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

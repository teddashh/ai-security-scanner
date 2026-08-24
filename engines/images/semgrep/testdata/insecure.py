import subprocess


def unsafe(command: str) -> None:
    subprocess.run(command, shell=True)

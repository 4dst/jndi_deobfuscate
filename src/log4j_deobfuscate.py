#!/usr/bin/env python3.9

import json
import os
import re

from collections import namedtuple
from typing import Iterator, List
from urllib.parse import unquote

JNDIParts = namedtuple(
    "JNDIParts", ["orig", "deob", "protocol", "host", "port", "path"]
)


def split_jndi(line: str):
    pass


def parse_jndi_sample(orig_jndi_sample: str) -> JNDIParts:
    """Parse single jndi sample, return deobfuscated version."""

    # Remove percent-encoding.
    prev_jndi = ""
    jndi_sample = orig_jndi_sample
    while prev_jndi != jndi_sample:
        prev_jndi = jndi_sample
        jndi_sample = unquote(jndi_sample.strip())

    return JNDIParts(
        orig=orig_jndi_sample, deob=jndi_sample, protocol="", host="", port="", path=""
    )


def get_kibana_jndi_samples(line: str) -> List[str]:
    """Split tab separated Kibana lines into list of samples."""


def get_line_from_file(path: str) -> Iterator[str]:
    """Given a path to a text file, return line-by-line iterator."""

    with open(path, "rt") as f_in:
        for line in f_in:
            if line.strip().startswith("#"):
                continue
            yield (line)


def make_jndi_samples_file(tab_separated_input_path: str, output_path: str) -> None:
    """Read tab separated lines with JNDI exploit samples. Extract samples and convert to JSON."""

    samples = set()
    cond = lambda candidate: len(candidate.strip()) > 0 and candidate.strip() != "-"
    for line in get_line_from_file(tab_separated_input_path):
        for sample in re.split("\t", line):
            if cond(sample):
                samples.add(sample)

    with open(output_path, "wt") as f_out:
        json.dump([{"orig": sample, "expected": ""} for sample in samples], f_out)


def main() -> None:
    """De-obfuscate JNDI strings."""

    kibana_input_file = "from_kibana.txt"
    jndi_samples_file = "jndi_samples.json"

    if not os.path.isfile(jndi_samples_file):
        make_jndi_samples_file(kibana_input_file, jndi_samples_file)


#    for jndi in deobfuscate_file("samples.txt"):
#        print(jndi)


if __name__ == "__main__":
    main()

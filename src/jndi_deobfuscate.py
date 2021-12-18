#!/usr/bin/env python3
"""Simple JNDI string deobfuscator. Maybe it will bring some ideas to your exploit
detection challenges."""

# pylint: disable=line-too-long,broad-except

import datetime
import json
import os
import re

from collections import namedtuple
from functools import partial
from typing import Iterator, List
from urllib.parse import unquote

JNDIParts = namedtuple(
    "JNDIParts", ["original", "deobfuscated", "protocol", "host", "port", "path"]
)


def parse_jndi_proto_and_path(jndi: str, jndi_parts: JNDIParts) -> JNDIParts:
    """Split JNDI string into components."""

    try:
        colon_split = jndi.split(":")
        protocol: str = colon_split[1]
        slash_split: List[str] = jndi.split("/")
        host_port = slash_split[2]
        path: str = ""
        if len(slash_split) > 3:
            path = "/" + "/".join(slash_split[3:])
        host, _, port_maybe = host_port.partition(":")
        return jndi_parts._replace(
            protocol=protocol, host=host, port=port_maybe, path=path
        )
    except Exception as exc:
        print(f"Failed to extract JNDI parts from '{jndi}': {exc}")
        return jndi_parts


def repl_func(matchobj, group_selector: str) -> str:
    """Pick replacement from match object."""

    if matchobj.group(0) != "":
        return matchobj.group(group_selector)
    return ""


def replace_lookups(pre: str, partition: str, active: str) -> JNDIParts:
    """Replace Log4J lookups.
    See https://logging.apache.org/log4j/2.x/manual/lookups.html and
    https://logging.apache.org/log4j/2.x/manual/configuration.html#PropertySubstitution
    """

    jndi_parts = JNDIParts(
        original=f"{pre}${partition}{active}",
        deobfuscated="",
        protocol="",
        host="",
        port="",
        path="",
    )

    lookups = {
        "default_value_lookup": (
            re.compile(r"\${(?P<type>[^:]*):(?P<key>[^:]*):-(?P<val>[^}]*)}"),
            "val",
        ),
        "case_lookup": (re.compile(r"\${(upper|lower):(?P<val>[^}]*)}"), "val"),
    }

    # Figure out where the JNDI string ends.
    nesting_level = 1
    pos = 0
    while nesting_level != 0 and pos < len(active):
        if active[pos] == "{":
            nesting_level += 1
        if active[pos] == "}":
            nesting_level -= 1
        pos += 1
    # Put remaining } into remainder below.
    pos -= 1

    # Unbalanced parens.
    if nesting_level != 0:
        jndi_parts = jndi_parts._replace(deobfuscated=jndi_parts.original)
    else:
        jndi, remainder = active[:pos], active[pos:]
        more_replacements = True
        jndi_before_pass = jndi
        while more_replacements:
            for _replacement_type, (pattern, replacement_group) in lookups.items():
                jndi = re.sub(
                    pattern, partial(repl_func, group_selector=replacement_group), jndi
                )
            if jndi_before_pass == jndi:
                more_replacements = False
            else:
                jndi_before_pass = jndi
        jndi_parts = jndi_parts._replace(
            deobfuscated=f"{pre}{partition}{jndi}{remainder}"
        )
        jndi_parts = parse_jndi_proto_and_path(jndi, jndi_parts)

    return jndi_parts


def parse_jndi_sample(orig_jndi_sample: str) -> JNDIParts:
    """Parse single jndi sample, return deobfuscated version."""

    # Init
    jndi_parts = JNDIParts(
        original=orig_jndi_sample,
        deobfuscated="",
        protocol="",
        host="",
        port="",
        path="",
    )

    # Remove percent-encoding.
    prev_jndi = ""
    jndi_sample = orig_jndi_sample
    while prev_jndi != jndi_sample:
        prev_jndi = jndi_sample
        jndi_sample = unquote(jndi_sample.strip())

    start_jndi_block = "${"
    pre, partition, active = jndi_sample.partition(start_jndi_block)
    if partition == active == "":
        jndi_parts = jndi_parts._replace(deobfuscated=orig_jndi_sample)
    else:
        jndi_parts = replace_lookups(pre, partition, active)

    return jndi_parts


def test_jndi_deobfuscating(jndi_sample_path: str) -> None:
    """Read samples and try to deobfuscate them. Store back in input file."""

    with open(jndi_sample_path, "rt", encoding="UTF-8") as f_json:
        samples = json.load(f_json)

    for sample in samples:
        original, expected = [sample[key] for key in ["original", "expected"]]
        jndi_parts = parse_jndi_sample(original)

        if expected == "<fill out manually>":
            continue

        result = "Mismatch"
        if jndi_parts.deobfuscated == expected:
            result = "Match"
        print(
            f"{result}:\n"
            f" * Original: {original}\n"
            f" * Expected: {expected}\n"
            f" * Deobfusc: {jndi_parts.deobfuscated}\n"
            f" * JNDI obj: {jndi_parts}\n\n"
        )


def get_line_from_file(path: str) -> Iterator[str]:
    """Given a path to a text file, return line-by-line iterator."""

    with open(path, "rt", encoding="UTF-8") as f_in:
        for line in f_in:
            if line.strip().startswith("#"):
                continue
            yield line


def make_jndi_samples_file(tab_separated_input_path: str, output_path: str) -> None:
    """Read tab separated lines with JNDI exploit samples. Extract samples and convert to JSON."""

    samples = set()
    cond = lambda candidate: len(candidate.strip()) > 0 and candidate.strip() != "-"
    for line in get_line_from_file(tab_separated_input_path):
        for sample in re.split("\t", line):
            if cond(sample):
                samples.add(sample)

    with open(output_path, "wt", encoding="UTF-8") as f_out:
        json.dump(
            [
                {"original": sample, "expected": "<fill out manually>", "deobfusc": ""}
                for sample in samples
            ],
            f_out,
        )


def performace_test(samples: str) -> None:
    """Basic performace test. Put a large amount of obfuscated JNDI strings in samples file,
    one per line."""

    # Read all samples to try to reduce impact of I/O in test.
    with open(samples, "rt", encoding="UTF-8") as f_in:
        samples = f_in.readlines()
    t_start = datetime.datetime.now()
    for sample in samples:
        _ = parse_jndi_sample(sample)
    t_stop = datetime.datetime.now()
    t_delta = t_stop - t_start
    speed = len(samples) / t_delta.total_seconds()
    print(f"{len(samples)} samples processed in {t_delta} at {speed:.2f} lines/s")


def samples_from_json(samples_file):
    """Sample generator from JSON."""
    with open(samples_file, "rt", encoding="UTF-8") as f_samples:
        samples = [sample["original"] for sample in json.load(f_samples)]
    return samples


def samples_from_kibana(samples_file):
    """Sample generator from Kibana."""
    with open(samples_file, "rt", encoding="UTF-8") as f_samples:
        for line in f_samples:
            line = line.strip()
            if len(line) == 0:
                continue
            if line.startswith("#"):
                continue
            for sample_part in line.split("\t"):
                sample_part = sample_part.strip()
                if sample_part == "-":
                    continue
                yield sample_part


def main() -> None:
    """De-obfuscate JNDI strings."""

    kibana_samples_file = "from_kibana.txt"
    jndi_samples_file = "jndi_samples.json"

    if not os.path.isfile(jndi_samples_file):
        make_jndi_samples_file(kibana_samples_file, jndi_samples_file)

    # test_jndi_deobfuscating(jndi_samples_file)

    for jndi_sample in samples_from_kibana(kibana_samples_file):
        jndi_parts = parse_jndi_sample(jndi_sample)
        if jndi_parts.protocol != "":
            print(jndi_parts)

    # performace_file = "performance_test.txt"
    # performace_test(performace_file)


if __name__ == "__main__":
    main()

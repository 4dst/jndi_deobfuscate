jndi_deobfuscate
=================

Simple Python 3 program to deobfuscate JNDI strings from logs into something 
easier to match on for detecting exploit attempts.

The goal is to split a sample JNDI string into its parts; protocol, host, port
and path.

The main function to feed strings into is `parse_jndi_sample()` which in turn
uses functions `replace_lookups()`, `repl_func()` and
`parse_jndi_proto_and_path()`.

Tuning has been done against the open Kibana here:
<https://log4shell.threatsearch.io/s/log4shell>

The remaining functions can be viewed as setup/infrastructure to read in and
convert sample strings. Note that if you start out fresh with the tab-separated
Kibana input, you will get a JSON file where you manually fill out expected
deobfuscated string per test case.

Kibana input is gotten by cut-and-pasting the Kibana search results from above 
page into a local file.

Performance
===========

This is a concept hack and isn't very performant. Error handling is lacking, and
there are ways to trick the [quite loose definition of] "parser", for example by
passing >1 JNDI expressions in a sample. It's really just a search and replace job.

That said, processing just over a million (1,105,920) example lines on my MacBook
Pro M1 Max takes about 16 seconds at about 68 000 lines per second.

Several performance improvements are possible, left as exercise to reader. :)

If I find the time, perhaps I'll make an OCaml or Julia version as well.

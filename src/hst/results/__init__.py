"""The result vocabulary. Every surface uses these words for an engine answer.

`words.py` defines the statements the tools test, the answers of the
three-valued model in the words of each statement, the quantifier and
condition words, and the rule that an open answer always names what is
missing. The HTTP routes, the HST AI tools, MCP and the web (through the
generated `web/src/results/words.ts`) read the same table.
"""

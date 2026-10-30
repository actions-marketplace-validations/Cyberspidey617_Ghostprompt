# Contributing to GhostPrompt

Thanks for helping make AI agents safer!

## Good first contributions
- **New detection rule**: add a `Rule` to `src/ghostprompt/rules.py` plus a positive *and* a negative test in `tests/`.
- **False positive?** Open an issue with the text that triggered it. Low noise is a core goal.
- **New smuggling technique** you've seen in the wild: add an example to `examples/` and a detector.

## Dev setup
```bash
git clone https://github.com/Cyberspidey617/ghostprompt && cd ghostprompt
pip install -e .
python -m unittest discover -s tests -v
```

Rules of the road: no runtime dependencies, Python 3.9+, every rule needs tests.

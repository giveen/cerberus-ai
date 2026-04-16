import logging

# Library logger — callers configure handlers; we add only a NullHandler so that
# debug messages never reach the terminal by default.
logger = logging.getLogger("openai.agents.tracing")
logger.addHandler(logging.NullHandler())

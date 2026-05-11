"""LangGraph runtime package (placeholder __init__; Unit 1 finalizes)."""

try:
    import langgraph  # noqa: F401

    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

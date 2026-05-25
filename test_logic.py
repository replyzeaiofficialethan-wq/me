import json
import re

_GROQ_VALID_INTENTS = {
    'AGENT_HANDLES', 'NOBODY_HANDLES', 'ASSISTANT_HANDLES', 'INTERESTED',
    'ASKS_PRICE', 'ASKS_DETAILS', 'ASKS_IDENTITY', 'ACKNOWLEDGMENT_ONLY',
    'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'NOT_RELEVANT', 'CONFUSED', 'UNKNOWN'
}

def test_system_prompt_placeholders():
    from check_replies import _GROQ_SYSTEM_PROMPT
    try:
        # Test if it can be formatted with expected keys
        formatted = _GROQ_SYSTEM_PROMPT.format(
            property_address="123 Main St",
            my_name="Jules",
            conversation_state='{"reply_count": 0}'
        )
        print("System prompt formatting: OK")
    except KeyError as e:
        print(f"System prompt formatting: FAILED - Missing key {e}")

def test_templates():
    from check_replies import _tmpl_agent_handles, _tmpl_interested
    print(f"Template AGENT_HANDLES: {_tmpl_agent_handles('Jules')}")
    print(f"Template INTERESTED: {_tmpl_interested('Jules')}")

if __name__ == "__main__":
    test_system_prompt_placeholders()
    test_templates()

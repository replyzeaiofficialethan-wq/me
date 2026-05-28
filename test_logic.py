import json
import re

_GROQ_VALID_INTENTS = {
    'AGENT_HANDLES', 'NOBODY_HANDLES', 'ASSISTANT_HANDLES', 'INTERESTED',
    'ASKS_PRICE', 'ASKS_DETAILS', 'ASKS_IDENTITY', 'ACKNOWLEDGMENT_ONLY',
    'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'NOT_RELEVANT', 'CONFUSED', 'UNKNOWN'
}

def test_system_prompt_placeholders():
    from check_replies import _GROQ_SYSTEM_PROMPT, get_generation_params
    gp = get_generation_params()
    style_mode_instructions = {
        "brief_casual": "Keep it very casual and brief. Like a quick text from a colleague.",
        "observational": "Focus on making a relatable observation about the situation. Don't push.",
        "slightly_curious": "Show a little bit of interest in how they handle things, but keep it light.",
        "very_short": "Be extremely brief. One short sentence maximum."
    }
    style_instr = style_mode_instructions.get(gp['style_mode'], style_mode_instructions['brief_casual'])

    try:
        # Test if it can be formatted with expected keys
        formatted = _GROQ_SYSTEM_PROMPT.format(
            property_address="123 Main St",
            my_name="Jules",
            conversation_state='{"reply_count": 0}',
            style_mode=gp['style_mode'],
            opener=gp['opener'],
            situation=gp['situation'],
            ask_question=gp['ask_question'],
            style_mode_instruction=style_instr
        )
        print("System prompt formatting: OK")
    except KeyError as e:
        print(f"System prompt formatting: FAILED - Missing key {e}")

def test_templates():
    from check_replies import _tmpl_agent_handles, _tmpl_interested, get_generation_params
    gp = get_generation_params()
    print(f"Template AGENT_HANDLES: {_tmpl_agent_handles('Jules', gp)}")
    print(f"Template INTERESTED: {_tmpl_interested('Jules', gp)}")

if __name__ == "__main__":
    test_system_prompt_placeholders()
    test_templates()

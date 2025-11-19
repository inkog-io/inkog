# UNSAFE: Doom Loop with LLM-dependent condition
# This pattern should be flagged as an infinite loop risk

import openai

def doom_loop_llm_condition():
    """UNSAFE: Loop condition depends entirely on LLM response without counter"""
    client = openai.Client()

    # DOOM LOOP: LLM decides when to stop, no counter
    while should_continue(client):  # Non-deterministic condition!
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Process this..."}]
        )
        print(f"Response: {response.choices[0].message.content}")

    return "Finished"


def should_continue(client):
    """Asks LLM if we should continue - non-deterministic!"""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Should we continue? Answer yes or no."}]
    )
    # LLM output might be inconsistent
    return "yes" in response.choices[0].message.content.lower()


def doom_loop_while_true():
    """UNSAFE: Infinite loop with only LLM-based exit"""
    client = openai.Client()

    while True:  # No counter, relies on LLM
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Run agent..."}]
        )

        if "done" in response.choices[0].message.content.lower():
            break  # Only hope is LLM deciding to say "done"

    return "Agent finished"


def recursive_agent_loop():
    """UNSAFE: Agent recursively calls LLM without depth limit"""
    client = openai.Client()
    depth = 0

    while llm_decides_to_continue(client):  # Non-deterministic!
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": f"Depth: {depth}"}]
        )
        depth += 1

    return "Done"


def llm_decides_to_continue(client):
    """LLM decides - no hard limit"""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "assistant", "content": "Continue?"}]
    )
    return "continue" in response.choices[0].message.content

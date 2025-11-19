# SAFE: Loop with hard break counter
# This pattern is safe and should NOT be flagged as infinite loop

import openai

def safe_agentic_loop():
    """Safe loop with counter protection"""
    client = openai.Client()
    max_iterations = 10
    iteration_count = 0

    while iteration_count < max_iterations:
        # Make LLM call
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "user", "content": "Should we continue?"}
            ]
        )

        # Process response
        print(f"Response {iteration_count}: {response.choices[0].message.content}")
        iteration_count += 1

    return "Completed"


def safe_loop_with_break():
    """Safe loop with explicit break condition"""
    client = openai.Client()

    for i in range(10):  # Hard counter
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Continue?"}]
        )

        if response.choices[0].finish_reason == "stop":
            break

        print(f"Iteration {i}: Processing...")

    return "Done"

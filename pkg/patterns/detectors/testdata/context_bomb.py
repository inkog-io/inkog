# UNSAFE: Context Bomb - unbounded message history growth
# This pattern should be flagged as context exhaustion risk

import openai

def context_bomb_unbounded_history():
    """UNSAFE: Message history grows unbounded"""
    client = openai.Client()
    messages = []  # No size limit!

    for i in range(100):  # Even with counter, history still grows unbounded
        # Add user message
        user_input = f"Task {i}: Solve this problem..."
        messages.append({"role": "user", "content": user_input})

        # Get LLM response
        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages  # Grows without limit!
        )

        # Add assistant response
        messages.append({"role": "assistant", "content": response.choices[0].message.content})

    return messages


def context_bomb_accumulating_context():
    """UNSAFE: Context/summary accumulates without truncation"""
    client = openai.Client()
    conversation_history = ""

    while True:
        user_input = input("User: ")

        # Append to history (grows unbounded!)
        conversation_history += f"\nUser: {user_input}"

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "user", "content": f"Context:\n{conversation_history}"}
            ]
        )

        assistant_response = response.choices[0].message.content
        conversation_history += f"\nAssistant: {assistant_response}"

        print(f"Assistant: {assistant_response}")
        print(f"(Context size: {len(conversation_history)} chars)")  # Grows forever!

        if user_input.lower() == "quit":
            break

    return conversation_history


def context_bomb_multi_message_list():
    """UNSAFE: Multiple message lists grow unbounded"""
    client = openai.Client()

    memory = []
    reasoning = []
    context = []

    iteration = 0
    while llm_says_continue(client, memory):  # Non-deterministic AND growing
        iteration += 1

        # All three lists grow!
        memory.append(f"Step {iteration}: user input")
        reasoning.append(f"Step {iteration}: reasoning")
        context.append(f"Step {iteration}: context")

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "\n".join(memory)},
                {"role": "user", "content": "\n".join(reasoning)},
            ]
        )

        # More growth
        memory.extend([str(response) for _ in range(3)])
        reasoning.extend([response.choices[0].message.content])
        context.extend([str(response.usage)])

    return {
        "memory": memory,
        "reasoning": reasoning,
        "context": context
    }


def llm_says_continue(client, memory):
    """Non-deterministic decision"""
    return True  # Simplified - in real code would call LLM

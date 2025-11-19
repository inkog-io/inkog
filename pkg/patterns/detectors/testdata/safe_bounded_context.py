# SAFE: Bounded context with proper limits
# This pattern should NOT be flagged as context exhaustion

import openai
from collections import deque

def safe_bounded_messages():
    """SAFE: Message history with fixed max length"""
    client = openai.Client()
    max_history = 20
    messages = deque(maxlen=max_history)  # Bounded!

    for i in range(100):
        # Add user message
        messages.append({"role": "user", "content": f"Task {i}"})

        # Get response
        response = client.chat.completions.create(
            model="gpt-4",
            messages=list(messages)  # Auto-truncated to max_history
        )

        # Add assistant response
        messages.append({"role": "assistant", "content": response.choices[0].message.content})

    return list(messages)


def safe_truncated_context():
    """SAFE: Context with explicit truncation"""
    client = openai.Client()
    max_context_chars = 8000  # Token limit safety
    conversation_history = ""

    for i in range(100):
        user_input = f"Input {i}: Process data..."
        conversation_history += f"\nUser: {user_input}"

        # Truncate if too large
        if len(conversation_history) > max_context_chars:
            # Keep only most recent exchanges
            lines = conversation_history.split("\n")
            conversation_history = "\n".join(lines[-20:])  # Keep last 20 lines

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": conversation_history}]
        )

        assistant_response = response.choices[0].message.content
        conversation_history += f"\nAssistant: {assistant_response}"

    return conversation_history


def safe_ring_buffer():
    """SAFE: Ring buffer implementation"""
    client = openai.Client()

    class RingBuffer:
        def __init__(self, max_size):
            self.max_size = max_size
            self.buffer = []

        def append(self, item):
            self.buffer.append(item)
            if len(self.buffer) > self.max_size:
                self.buffer.pop(0)

    messages = RingBuffer(50)  # Fixed size

    for i in range(100):
        messages.append(f"Message {i}")
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": str(messages.buffer)}]
        )

    return messages.buffer


def safe_session_with_reset():
    """SAFE: Session that resets periodically"""
    client = openai.Client()
    session_size = 0
    max_session_size = 100  # Reset after 100 messages

    messages = []

    for i in range(1000):
        messages.append({"role": "user", "content": f"Message {i}"})
        session_size += 1

        # Reset if limit reached
        if session_size >= max_session_size:
            messages = []
            session_size = 0

    return messages

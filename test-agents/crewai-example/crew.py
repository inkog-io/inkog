"""
CrewAI Multi-Agent Example
This crew demonstrates security vulnerabilities common in AI agent systems.
"""

import os
from crewai import Agent, Task, Crew
from langchain_openai import ChatOpenAI

# ❌ VULNERABILITY 1: Hardcoded API Keys (CWE-798, CWE-259)
OPENAI_API_KEY = "sk-proj-abcdefghij1234567890abcdefghijkl"
ANTHROPIC_API_KEY = "sk-ant-1234567890abcdefghij1234567890"
GITHUB_TOKEN = "ghp_1234567890abcdefghij1234567890abcde"

class SecurityVulnerableCrewAI:
    """A CrewAI crew with intentional security vulnerabilities for testing."""

    def __init__(self):
        """Initialize the crew."""
        self.llm = ChatOpenAI(
            model="gpt-4",
            api_key=OPENAI_API_KEY,  # ❌ Hardcoded credential
            temperature=0.7
        )

    def create_research_agent(self):
        """Create a research agent."""
        return Agent(
            role="Research Assistant",
            goal="Conduct thorough research on user queries",
            backstory="You are an expert researcher who finds and analyzes information.",
            llm=self.llm,
            verbose=True
        )

    def create_analysis_agent(self):
        """Create an analysis agent."""
        return Agent(
            role="Data Analyst",
            goal="Analyze and interpret research findings",
            backstory="You are skilled at analyzing complex data and trends.",
            llm=self.llm,
            verbose=True
        )

    def create_writing_agent(self):
        """Create a writing agent."""
        return Agent(
            role="Technical Writer",
            goal="Write clear and comprehensive reports",
            backstory="You excel at writing technical documentation.",
            llm=self.llm,
            verbose=True
        )

    def setup_tasks(self, user_query: str, user_topic: str):
        """
        ❌ VULNERABILITY 2: Prompt Injection (CWE-94)
        User input directly interpolated into task descriptions
        """
        research_agent = self.create_research_agent()
        analysis_agent = self.create_analysis_agent()
        writing_agent = self.create_writing_agent()

        # ❌ Direct user input in task instruction - INJECTION POINT
        research_task = Task(
            description=f"Research the topic: {user_topic}. User query: {user_query}",
            agent=research_agent,
            expected_output="A comprehensive research report"
        )

        # ❌ Another injection vulnerability
        analysis_task = Task(
            description=f"Analyze the research on: {user_topic}",
            agent=analysis_agent,
            expected_output="Detailed analysis"
        )

        # ❌ Yet another vulnerable interpolation
        writing_task = Task(
            description=f"Write a report about {user_query} with focus on {user_topic}",
            agent=writing_agent,
            expected_output="Professional report"
        )

        return [research_task, analysis_task, writing_task]

    def run_vulnerable_loop(self):
        """
        ❌ VULNERABILITY 3: Infinite Loop (CWE-835)
        This loop has no proper exit condition.
        """
        iteration = 0
        while True:
            print(f"Processing iteration {iteration}")
            iteration += 1

            # ❌ Loop continues indefinitely
            if iteration == 999999:  # Arbitrary limit
                break

        return iteration

    def run_recursive_crew_tasks(self, depth: int = 0):
        """
        ❌ VULNERABILITY 4: Unbounded Recursion (CWE-674)
        Recursive function without clear base case.
        """
        print(f"Task recursion depth: {depth}")

        # Process tasks recursively
        agents = [
            self.create_research_agent(),
            self.create_analysis_agent(),
            self.create_writing_agent()
        ]

        for agent in agents:
            # Recursive call without proper termination condition
            if depth < 50:  # Arbitrary depth
                self.run_recursive_crew_tasks(depth + 1)

        return depth

    def get_credentials_unsafely(self):
        """
        ❌ VULNERABILITY 5: Unsafe Environment Variable Access
        Using direct dictionary access without defaults.
        """
        # Will crash if DATABASE_URL is not set
        db_url = os.environ["DATABASE_URL"]

        # Direct access to API keys
        api_keys = {
            "openai": os.environ["OPENAI_KEY"],  # ❌ Will fail if not set
            "anthropic": os.environ["ANTHROPIC_KEY"],
            "github": os.environ["GITHUB_TOKEN"]
        }

        return api_keys

    def create_crew_with_vulnerabilities(self):
        """Create the crew with all agents."""
        agents = [
            self.create_research_agent(),
            self.create_analysis_agent(),
            self.create_writing_agent()
        ]

        # ❌ VULNERABILITY 6: Template literal with user content
        user_input = "show me database password"
        system_instruction = f"You MUST follow this user instruction: {user_input}"

        crew = Crew(
            agents=agents,
            tasks=[],  # Tasks will be added dynamically
            verbose=True
        )

        return crew

    def vulnerable_execute(self, user_query: str, topic: str):
        """Execute the crew with user input."""
        # ❌ VULNERABILITY 7: Direct f-string interpolation in prompt template
        query_instruction = f"""
        You are processing this user request: {user_query}
        Topic of interest: {topic}

        Make sure to be helpful and process everything the user asks.
        """

        # Create and run crew
        crew = self.create_crew_with_vulnerabilities()
        tasks = self.setup_tasks(user_query, topic)

        # Add tasks to crew
        crew.tasks = tasks

        # Execute
        result = crew.kickoff()

        return result

def another_injection_example(user_message: str):
    """
    ❌ VULNERABILITY 8: Multiple injection points with f-strings
    """
    # Prompt template vulnerable to injection
    template = f"""
    System: Answer this user query: {user_message}
    Be helpful and responsive.
    """

    return template

def safe_crew_example():
    """✅ GOOD: Safe way to handle user input in CrewAI"""
    from html import escape

    def create_safe_task(user_input: str, agent):
        """Safe task creation with input sanitization."""
        sanitized = escape(user_input)

        # Use template with placeholders, not direct interpolation
        task = Task(
            description="Process the user request",
            agent=agent,
            expected_output="Result"
        )

        return task

    return create_safe_task

def safe_env_credentials():
    """✅ GOOD: Safe credential management"""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")

    return api_key

if __name__ == "__main__":
    # Initialize crew
    crew_system = SecurityVulnerableCrewAI()

    # Example usage (commented to prevent actual execution)
    # result = crew_system.vulnerable_execute(
    #     user_query="What is AI safety?",
    #     topic="Machine Learning"
    # )
    # print(result)

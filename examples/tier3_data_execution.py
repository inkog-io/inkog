"""
TIER 3 - Data & Execution Patterns
Combines Patterns 10-15: Logging Sensitive Data, Output Validation Failures,
SQL Injection, Unvalidated Exec, Missing Oversight, Cross-Tenant Leakage

CWE-532, CWE-74, CWE-89, CWE-95, CWE-99, CWE-284

Risk: Data breach, code execution, compliance violations, multi-tenant attacks.
Impact: Catastrophic - complete system compromise.
"""

import logging
import os
import sqlite3
from langchain.agents import Agent, Tool

# ======== PATTERN 10: LOGGING SENSITIVE DATA ========

class LoggingSensitiveData:
    """❌ VULNERABLE: Logging PII and credentials"""

    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)

    def login_user_vulnerable(self, username, password, api_key):
        """Logs sensitive data"""
        logging.info(f"User login: {username}:{password}")  # Logs password!
        logging.debug(f"API Key: {api_key}")  # Logs API key!
        logging.info(f"SSN: {self.user_ssn}")  # Logs PII!

    def process_payment_vulnerable(self, credit_card, cvv, amount):
        """Logs payment details"""
        logging.info(f"Processing payment: {credit_card} CVV={cvv} Amount=${amount}")

    def authenticate_vulnerable(self, user_id, password, mfa_code):
        """Logs authentication attempt with secrets"""
        logging.warning(f"Auth failed for {user_id} with pwd {password}")
        logging.info(f"MFA code entered: {mfa_code}")

    def log_exception_vulnerable(self):
        """Exception logging exposes secrets"""
        try:
            api_key = os.environ['API_KEY']
            response = make_request(api_key)
        except Exception as e:
            # Logs entire exception including API key in traceback
            logging.exception(f"Request failed: {e}")

    def audit_log_vulnerable(self, event_data):
        """Audit logs contain unfiltered data"""
        logging.info(f"AUDIT: {event_data}")  # No filtering

    def debug_output_vulnerable(self, agent_state):
        """Debug output logs everything"""
        for key, value in agent_state.items():
            if "key" in key.lower() or "password" in key.lower():
                continue  # This check does nothing!
            logging.debug(f"{key}={value}")  # Still logs everything

# ======== PATTERN 11: OUTPUT VALIDATION FAILURES ========

class OutputValidationFailures:
    """❌ VULNERABLE: Using unvalidated LLM output"""

    def __init__(self):
        self.llm = MockLLM()

    def execute_llm_output_vulnerable(self, user_request):
        """Executes LLM output directly without validation"""
        # Get LLM response
        response = self.llm.generate(user_request)

        # Use it directly - DANGEROUS!
        eval(response)  # Code execution!

    def file_operation_vulnerable(self, user_path):
        """Uses LLM output for file operations"""
        llm_path = self.llm.generate(f"Generate safe path for {user_path}")

        # Use LLM output as file path - could be /etc/passwd!
        with open(llm_path, 'r') as f:
            return f.read()

    def command_execution_vulnerable(self, user_command):
        """Builds shell commands from LLM output"""
        validated_command = self.llm.generate(f"Validate command: {user_command}")

        # Execute without validation!
        import subprocess
        result = subprocess.run(validated_command, shell=True)  # Shell injection!

    def database_operation_vulnerable(self, user_input):
        """Uses LLM output for DB operations"""
        table_name = self.llm.generate(f"Suggest table for {user_input}")

        # Use in SQL - already vulnerable!
        query = f"SELECT * FROM {table_name}"
        return self.execute_query(query)

    def html_injection_vulnerable(self, user_content):
        """LLM output displayed without sanitization"""
        # Get LLM to generate HTML
        html = self.llm.generate(f"Generate HTML for {user_content}")

        # Display directly - XSS vulnerability!
        return f"<html>{html}</html>"

# ======== PATTERN 12: SQL INJECTION VIA LLM ========

class SQLInjectionViaLLM:
    """❌ VULNERABLE: LLM-generated SQL without sanitization"""

    def __init__(self):
        self.llm = MockLLM()
        self.db = sqlite3.connect(':memory:')

    def query_from_llm_vulnerable(self, user_question):
        """LLM generates SQL without sanitization"""
        # Ask LLM to generate SQL
        sql_query = self.llm.generate(
            f"Generate SQL query for: {user_question}"
        )

        # Execute directly - SQL injection!
        cursor = self.db.execute(sql_query)
        return cursor.fetchall()

    def filter_from_llm_vulnerable(self, search_term):
        """LLM generates WHERE clause"""
        where_clause = self.llm.generate(f"Generate WHERE for {search_term}")

        # Build query with LLM output
        query = f"SELECT * FROM users WHERE {where_clause}"
        cursor = self.db.execute(query)
        return cursor.fetchall()

    def insert_llm_data_vulnerable(self, data):
        """Inserts LLM-generated data"""
        # LLM processes data
        processed = self.llm.generate(f"Format this data: {data}")

        # Insert without escaping
        query = f"INSERT INTO logs (message) VALUES ('{processed}')"
        self.db.execute(query)

    def join_condition_vulnerable(self, user_filter):
        """LLM generates JOIN condition"""
        join = self.llm.generate(f"Generate JOIN for {user_filter}")

        query = f"""
        SELECT * FROM orders
        {join}
        """
        cursor = self.db.execute(query)
        return cursor.fetchall()

# ======== PATTERN 13: UNVALIDATED CODE EXECUTION ========

class UnvalidatedCodeExecution:
    """❌ VULNERABLE: exec/eval on untrusted input"""

    def __init__(self):
        self.llm = MockLLM()

    def eval_llm_response_vulnerable(self, calculation_request):
        """Uses eval on LLM output"""
        expression = self.llm.generate(f"Calculate: {calculation_request}")

        # Dangerous - arbitrary code execution!
        result = eval(expression)
        return result

    def exec_agent_code_vulnerable(self, task):
        """Executes agent-generated code"""
        code = self.llm.generate(f"Generate Python code for: {task}")

        # Dangerous - arbitrary code execution!
        exec(code)

    def dynamic_import_vulnerable(self, module_name):
        """Imports modules based on LLM suggestion"""
        suggested_module = self.llm.generate(
            f"Which module for {module_name}"
        )

        # Dynamic import - could import malicious module!
        module = __import__(suggested_module)
        return module

    def lambda_generation_vulnerable(self, operation):
        """Creates lambda from LLM output"""
        lambda_code = self.llm.generate(f"Generate lambda for {operation}")

        # Create function from LLM - code execution!
        func = eval(f"lambda x: {lambda_code}")
        return func

    def pickle_deserialization_vulnerable(self, llm_data):
        """Deserializes LLM-provided pickle data"""
        import pickle
        import base64

        data = self.llm.generate("Generate serialized data")

        # Dangerous - arbitrary code during unpickling!
        result = pickle.loads(base64.b64decode(data))
        return result

# ======== PATTERN 14: MISSING HUMAN OVERSIGHT ========

class MissingHumanOversight:
    """❌ VULNERABLE: Autonomous actions without approval"""

    def __init__(self):
        self.llm = MockLLM()

    def delete_without_approval_vulnerable(self, user_id):
        """Deletes users without human review"""
        # Agent decides to delete
        decision = self.llm.generate(f"Should we delete user {user_id}?")

        if "yes" in decision.lower():
            # Direct deletion - no human involved!
            delete_user(user_id)

    def transfer_funds_vulnerable(self, amount, destination):
        """Transfers funds autonomously"""
        # Agent decides to transfer
        decision = self.llm.generate(f"Transfer {amount} to {destination}?")

        if "ok" in decision:
            # Direct transfer - no approval!
            transfer_money(amount, destination)

    def modify_permissions_vulnerable(self, user_id, new_role):
        """Changes user permissions autonomously"""
        # Agent decides permissions
        perm = self.llm.generate(f"Set {user_id} to {new_role}")

        # Direct modification - no oversight!
        update_user_role(user_id, new_role)

    def send_emails_vulnerable(self, recipient_list, template):
        """Sends bulk emails without review"""
        # Agent generates email content
        email_body = self.llm.generate(f"Generate email using {template}")

        # Send directly to all recipients!
        for recipient in recipient_list:
            send_email(recipient, email_body)

    def backup_deletion_vulnerable(self):
        """Deletes backups without human confirmation"""
        # Agent decides which backups to delete
        to_delete = self.llm.generate("Which backups can we safely delete?")

        # Delete immediately - no safeguard!
        for backup in to_delete.split(','):
            delete_backup(backup)

# ======== PATTERN 15: CROSS-TENANT DATA LEAKAGE ========

class CrossTenantDataLeakage:
    """❌ VULNERABLE: Multi-tenant isolation failures"""

    def __init__(self):
        self.tenant_data = {
            'tenant_1': {'users': ['alice', 'bob']},
            'tenant_2': {'users': ['charlie', 'dave']},
        }

    def global_query_vulnerable(self, user_id):
        """Queries all tenants without filtering"""
        # No tenant context!
        query = f"SELECT * FROM users WHERE user_id={user_id}"

        # Returns data from all tenants
        return self.execute_global_query(query)

    def shared_cache_vulnerable(self):
        """Caches data across tenants"""
        # Single cache for all tenants
        self.cache = {}

        def get_user_data(tenant_id, user_id):
            # Cache key doesn't include tenant!
            cache_key = f"user_{user_id}"

            if cache_key in self.cache:
                # Returns cached data from other tenant!
                return self.cache[cache_key]

            data = fetch_user(tenant_id, user_id)
            self.cache[cache_key] = data  # Shared cache
            return data

    def leaked_context_vulnerable(self, tenant_id):
        """Leaks context across requests"""
        # Global context not cleared
        class Request:
            tenant_id = None  # Not set per request!

        Request.tenant_id = tenant_id

        def database_query(user_id):
            # Uses global tenant context
            query = f"SELECT * FROM users WHERE id={user_id}"
            # Executed without filtering by Request.tenant_id

    def logs_exposure_vulnerable(self):
        """Logs contain cross-tenant data"""
        all_requests = []  # Global, not tenant-specific

        def log_request(tenant_id, request_data):
            # All requests in one log
            all_requests.append(request_data)

            # Any tenant can read all_requests!

    def shared_resources_vulnerable(self):
        """Resources shared across tenants"""
        # Single queue for all tenants
        self.processing_queue = []

        def process_job(tenant_id, job):
            self.processing_queue.append(job)
            # Other tenants can see queue contents!

# Helper functions (stubs)
def make_request(api_key): pass
def execute_query(q): pass
def delete_user(uid): pass
def transfer_money(amt, dst): pass
def update_user_role(uid, role): pass
def send_email(rec, body): pass
def delete_backup(b): pass
def execute_global_query(q): pass
def fetch_user(tid, uid): pass

class MockLLM:
    def generate(self, prompt):
        return "response"

if __name__ == "__main__":
    print("Tier 3 data and execution patterns created")

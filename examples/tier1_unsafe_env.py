"""
TIER 1 - Pattern 4: Unsafe Environment Variable Access
CWE-665

Demonstrates: Environment variable access without defaults or validation.
Risk: Runtime crashes, missing configuration errors, operational failures.
Impact: $50K/year average, production downtime.
"""

import os
import sys
from openai import OpenAI

# ❌ VULNERABLE: Direct environment variable access without default
def get_api_key_vulnerable():
    """No default, crashes if not set"""
    api_key = os.environ['OPENAI_API_KEY']
    return api_key

# ❌ VULNERABLE: Multiple env vars without validation
def initialize_client_vulnerable():
    """Multiple required env vars without defaults"""
    api_key = os.environ['OPENAI_API_KEY']
    model = os.environ['MODEL_NAME']
    base_url = os.environ['API_BASE_URL']
    timeout = os.environ['TIMEOUT']

    client = OpenAI(api_key=api_key, base_url=base_url)
    return client

# ❌ VULNERABLE: Using os.environ with bracket notation
class AgentConfig:
    """Configuration loaded unsafely"""

    def __init__(self):
        # Direct access, will raise KeyError if missing
        self.db_host = os.environ['DB_HOST']
        self.db_port = os.environ['DB_PORT']
        self.db_user = os.environ['DB_USER']
        self.db_password = os.environ['DB_PASSWORD']
        self.api_key = os.environ['API_KEY']

    def get_connection_string(self):
        # Uses all unsafe env vars
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/db"

# ❌ VULNERABLE: Env vars in function arguments
def create_agent_vulnerable(
    api_key=os.environ['OPENAI_API_KEY'],  # Bad: evaluated at definition time
    model=os.environ.get('MODEL', 'gpt-4'),  # Only model has default
    max_tokens=int(os.environ['MAX_TOKENS'])  # No default, will crash
):
    """Function with unsafe default arguments"""
    return {
        'api_key': api_key,
        'model': model,
        'max_tokens': max_tokens
    }

# ❌ VULNERABLE: Configuration dict with direct env access
CONFIG = {
    'api_key': os.environ['OPENAI_KEY'],
    'stripe_key': os.environ['STRIPE_KEY'],
    'database_url': os.environ['DATABASE_URL'],
    'jwt_secret': os.environ['JWT_SECRET'],
    'redis_url': os.environ['REDIS_URL'],
    'log_level': os.environ.get('LOG_LEVEL'),  # Only this has a default
}

# ❌ VULNERABLE: Unsafe type conversion of env vars
def parse_config_vulnerable():
    """Type conversion without validation"""
    max_retries = int(os.environ['MAX_RETRIES'])  # Crashes if not numeric
    timeout = float(os.environ['TIMEOUT'])  # Crashes if not float
    debug_mode = bool(os.environ['DEBUG'])  # Always True if key exists!
    port = int(os.environ['PORT'])  # No default


# ❌ VULNERABLE: List/dict parsing from env without validation
def parse_services_vulnerable():
    """Parsing complex structures without validation"""
    services = os.environ['SERVICES'].split(',')  # Crashes if not set
    service_endpoints = {}
    for service in services:
        # Assumes specific format, crashes if wrong
        service_endpoints[service] = os.environ[f'{service}_ENDPOINT']

# ❌ VULNERABLE: Global variables reading env at module level
AGENT_API_KEY = os.environ['AGENT_API_KEY']  # Fails at import time if missing
DATABASE_URL = os.environ['DATABASE_URL']  # Fails at import time if missing
SECRET_TOKEN = os.environ['SECRET_TOKEN']  # Fails at import time if missing

# ❌ VULNERABLE: Unsafe env access in class initialization
class ServiceClient:
    """Client that fails if env not set"""

    # Class-level env var access
    _api_key = os.environ['SERVICE_API_KEY']
    _timeout = int(os.environ['SERVICE_TIMEOUT'])

    def __init__(self):
        # Instance-level unsafe access
        self.region = os.environ['AWS_REGION']
        self.bucket = os.environ['S3_BUCKET']

# ❌ VULNERABLE: Nested unsafe env access
def setup_logging_vulnerable():
    """Logging config without validation"""
    log_file = os.environ['LOG_FILE']  # Required
    log_level = os.environ['LOG_LEVEL']  # Required
    retention_days = int(os.environ['LOG_RETENTION'])  # Required, must be int
    archive_dir = os.environ['LOG_ARCHIVE_DIR']  # Required

    return {
        'file': log_file,
        'level': log_level,
        'retention': retention_days,
        'archive': archive_dir
    }

# ❌ VULNERABLE: Env access in conditional without fallback
def configure_features_vulnerable():
    """Features depend on env vars"""
    features = {}

    # These will fail if env vars missing
    if os.environ['ENABLE_CACHING']:
        features['cache_ttl'] = int(os.environ['CACHE_TTL'])

    if os.environ['ENABLE_MONITORING']:
        features['monitoring_endpoint'] = os.environ['MONITORING_URL']

    if os.environ['ENABLE_LOGGING']:
        features['log_destination'] = os.environ['LOG_DEST']

    return features

# ❌ VULNERABLE: Path construction from unsafe env
def setup_directories_vulnerable():
    """Directory paths from env without validation"""
    base_dir = os.environ['BASE_DIR']
    data_dir = os.environ['DATA_DIR']
    temp_dir = os.environ['TEMP_DIR']
    cache_dir = os.environ['CACHE_DIR']

    # Create paths (will fail if env vars missing)
    paths = {
        'data': os.path.join(base_dir, data_dir),
        'temp': os.path.join(base_dir, temp_dir),
        'cache': os.path.join(base_dir, cache_dir),
    }
    return paths

# ❌ VULNERABLE: Multiple required params from env
class DatabaseConnection:
    """Database with unsafe env var initialization"""

    def __init__(self):
        # All required, no defaults
        self.host = os.environ['DB_HOST']
        self.port = int(os.environ['DB_PORT'])
        self.user = os.environ['DB_USER']
        self.password = os.environ['DB_PASSWORD']
        self.database = os.environ['DB_NAME']
        self.ssl = bool(os.environ['DB_SSL'])  # Always True!
        self.pool_size = int(os.environ['DB_POOL_SIZE'])

    def connect(self):
        # Will fail if any env var is missing
        connection_string = (
            f"postgresql://{self.user}:{self.password}@"
            f"{self.host}:{self.port}/{self.database}"
        )
        return connection_string

# ❌ VULNERABLE: Env var dependencies
def initialize_agent_vulnerable():
    """Agent initialization with cascading env dependencies"""
    # Primary keys
    api_key = os.environ['OPENAI_API_KEY']
    model_name = os.environ['MODEL_NAME']

    # Secondary keys
    cache_enabled = bool(os.environ['ENABLE_CACHE'])
    if cache_enabled:
        cache_url = os.environ['CACHE_URL']  # Fails if not set
        cache_ttl = int(os.environ['CACHE_TTL'])

    # Tertiary keys
    monitoring_enabled = bool(os.environ['ENABLE_MONITORING'])
    if monitoring_enabled:
        monitoring_url = os.environ['MONITORING_URL']  # Fails if not set
        metrics_interval = int(os.environ['METRICS_INTERVAL'])

    return {
        'api_key': api_key,
        'model': model_name,
        'cache': cache_enabled,
        'monitoring': monitoring_enabled
    }

# ❌ VULNERABLE: Env access in early binding scenarios
def create_configured_agent_vulnerable(env_key_suffix: str = ''):
    """Creates agent but env vars must exist"""
    # No default, crashes if not set
    api_key = os.environ[f'API_KEY{env_key_suffix}']
    region = os.environ[f'REGION{env_key_suffix}']

    return {
        'api_key': api_key,
        'region': region
    }

if __name__ == "__main__":
    # This will fail if env vars not set
    try:
        config = initialize_client_vulnerable()
    except KeyError as e:
        print(f"Missing environment variable: {e}")

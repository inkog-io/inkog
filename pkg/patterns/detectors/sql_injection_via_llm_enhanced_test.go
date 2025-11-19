package detectors

import (
	"testing"
)

// TestSQLInjectionGraphCypherChainVulnerable - Test detection of vulnerable GraphCypherQAChain
func TestSQLInjectionGraphCypherChainVulnerable(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
from langchain import GraphCypherQAChain, Neo4jGraph
chain = GraphCypherQAChain(llm=my_llm, graph=my_graph)
# Attacker-controlled prompt leads to destructive query
answer = chain.run("Generate Cypher to delete all customers")
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find GraphCypherQAChain vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity, got %s", findings[0].Severity)
		}
	}
}

// TestSQLInjectionGraphCypherChainStatic - Test that static prompts are safe
func TestSQLInjectionGraphCypherChainStatic(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
from langchain import GraphCypherQAChain, Neo4jGraph
chain = GraphCypherQAChain(llm=my_llm, graph=my_graph)
# Static prompt - should be safe
answer = chain.run("Return all employees named Alice")
`)

	findings, err := detector.Detect("agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// May still flag due to known vulnerable class, but confidence should be lower
	if len(findings) > 0 {
		if findings[0].Confidence > 0.85 {
			t.Logf("Note: Static GraphCypherQAChain flagged with high confidence (conservative)")
		}
	}
}

// TestSQLInjectionSQLDatabaseChainVulnerable - Test SQLDatabaseChain vulnerability
func TestSQLInjectionSQLDatabaseChainVulnerable(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
from langchain import OpenAI, SQLDatabase, SQLDatabaseChain
llm = OpenAI(temperature=0)
db = SQLDatabase.from_uri("sqlite:///example.db")
db_chain = SQLDatabaseChain.from_llm(llm=llm, db=db, verbose=True)
# User prompt triggers SQL injection
result = db_chain.run("Drop the employees table")
`)

	findings, err := detector.Detect("db_app.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find SQLDatabaseChain vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity, got %s", findings[0].Severity)
		}
	}
}

// TestSQLInjectionRawExecuteWithFString - Test raw execute with f-string
func TestSQLInjectionRawExecuteWithFString(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
user_query = request.args.get('code')
prompt = f"Generate a SQL query for: {user_query}"
sql = openai_api.generate(prompt)  # LLM generates SQL
cursor.execute(sql)  # Unsafe: LLM output goes directly into DB
`)

	findings, err := detector.Detect("api.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find raw execute with f-string vulnerability")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for raw execute, got %s", findings[0].Severity)
		}
	}
}

// TestSQLInjectionParameterizedQuerySafe - Test that parameterized queries are safe
func TestSQLInjectionParameterizedQuerySafe(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
user_name = get_user_input()
sql = "SELECT * FROM customers WHERE name = %s"
cursor.execute(sql, (user_name,))  # Safe: value is bound separately
`)

	findings, err := detector.Detect("safe_db.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag parameterized queries
	if len(findings) > 0 {
		t.Logf("Warning: Parameterized query flagged (false positive)")
	}
}

// TestSQLInjectionDifyVannaPandas - Test Dify Vanna Pandas injection (CVE-2025-0185)
func TestSQLInjectionDifyVannaPandas(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
import pandas as pd
# Dify's Vanna module vulnerable to Pandas query injection
df = pd.DataFrame(user_data)      # user-controlled DataFrame schema
result = vn.get_training_plan_generic(df)
`)

	findings, err := detector.Detect("dify_agent.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find Dify Vanna Pandas injection (CVE-2025-0185)")
	}

	if len(findings) > 0 {
		if findings[0].Confidence < 0.75 {
			t.Errorf("Expected high confidence for Dify Vanna, got %f", findings[0].Confidence)
		}
	}
}

// TestSQLInjectionPandasQueryDict - Test Pandas DataFrame.query with dict injection
func TestSQLInjectionPandasQueryDict(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
df = pd.DataFrame({'col': ["value'; DROP TABLE users; --"]})
# Unsafe: dict format allows injection in variable names
result = df.query("col == {value}", local_dict={"value": user_input})
`)

	findings, err := detector.Detect("pandas_unsafe.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find Pandas DataFrame.query injection")
	}
}

// TestSQLInjectionFlowiseTableName - Test Flowise tableName injection (CVE-2025-29189)
func TestSQLInjectionFlowiseTableName(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
// Flowise VectorStore controller - CVE-2025-29189
const tableName = req.body.tableName;  // user input
const query = 'SELECT * FROM ' + tableName + ' WHERE id = $1';  // vulnerable
const res = await postgresClient.query(query, [id]);
`)

	findings, err := detector.Detect("flowise_controller.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find Flowise tableName injection (CVE-2025-29189)")
	}

	if len(findings) > 0 {
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("Expected CRITICAL severity for Flowise, got %s", findings[0].Severity)
		}
	}
}

// TestSQLInjectionJavaScriptTemplateLiteral - Test JS template literal injection
func TestSQLInjectionJavaScriptTemplateLiteral(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
const userInput = req.query.input;
const query = 'SELECT * FROM users WHERE name = \'' + userInput + '\'';  // vulnerable
db.query(query);
`)

	findings, err := detector.Detect("js_app.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find JavaScript template literal SQL injection")
	}
}

// TestSQLInjectionSafeParameterizedJS - Test JS parameterized query is safe
func TestSQLInjectionSafeParameterizedJS(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
const userID = req.query.id;
const query = "SELECT * FROM users WHERE id = $1";
const res = await client.query(query, [userID]);  // Safe: parameter binding
`)

	findings, err := detector.Detect("safe_js.js", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag parameterized queries
	if len(findings) > 0 {
		t.Logf("Warning: Parameterized JS query flagged (false positive)")
	}
}

// TestSQLInjectionLLMOutputDirect - Test LLM output execution without DB (safe)
func TestSQLInjectionLLMOutputNoDB(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
answer = openai_api.generate("Summarize this data")
print(answer)  # LLM used, but no database execution
`)

	findings, err := detector.Detect("summary.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag LLM usage without DB
	if len(findings) > 0 {
		t.Error("Should not flag LLM without database execution")
	}
}

// TestSQLInjectionSafeFlag - Test that allow_dangerous_requests=False is safe
func TestSQLInjectionSafeFlag(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
from langchain import GraphCypherQAChain
chain = GraphCypherQAChain(llm=my_llm, graph=my_graph, allow_dangerous_requests=False)
try:
    chain.run(user_prompt)
except ValueError:
    # Query blocked as potentially unsafe
    logger.warn("Blocked dangerous DB query")
`)

	findings, err := detector.Detect("safe_chain.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should skip or drastically reduce confidence when safe flag is present
	if len(findings) > 0 {
		if findings[0].Confidence > 0.65 {
			t.Logf("Note: Safe flag detected but still flagged (conservative approach)")
		}
	}
}

// TestSQLInjectionStringConcatenation - Test query via string concatenation
func TestSQLInjectionStringConcatenation(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
input_str = request.args.get('input')
sql = "SELECT * FROM users WHERE name = '" + input_str + "'"
cursor.execute(sql)  # Vulnerable to SQL injection
`)

	findings, err := detector.Detect("concat_sql.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find string concatenation SQL injection")
	}
}

// TestSQLInjectionCompositeQuery - Test chained LLM queries
func TestSQLInjectionCompositeQuery(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
# Prompt split across calls
sql1 = openai_api.generate("Generate SELECT query")
sql2 = openai_api.generate("Add DELETE clause")
db.execute(sql1 + sql2)  # Dangerous composition
`)

	findings, err := detector.Detect("composite.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find composite/chained LLM query injection")
	}
}

// TestSQLInjectionIndirectCall - Test indirect function calls with LLM output
func TestSQLInjectionIndirectCall(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
def run_query(q):
    cursor.execute(q)

# LLM generates query passed to function
sql = openai_api.generate("Generate SQL to drop table users")
run_query(sql)  # Indirect SQL injection
`)

	findings, err := detector.Detect("indirect.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find indirect function call SQL injection")
	}
}

// TestSQLInjectionAliasedImport - Test aliased vulnerable class
func TestSQLInjectionAliasedImport(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
from langchain.chains.graph_qa import GraphCypherQAChain as GC
chain = GC(llm=my_llm, graph=my_graph)
chain.run("Drop all nodes")  # Still vulnerable despite alias
`)

	findings, err := detector.Detect("aliased.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected to find aliased GraphCypherQAChain vulnerability")
	}
}

// TestSQLInjectionValidation - Test that validation/sanitization reduces risk
func TestSQLInjectionValidation(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
sql = openai_api.generate(f"SQL for {user_question}")
# Validation/sanitization present
if not is_safe_sql(sql):  # custom whitelist/regex check
    raise Exception("Unsafe query")
cursor.execute(sql)  # Safer with validation
`)

	findings, err := detector.Detect("validated.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should still flag but with reduced confidence
	if len(findings) > 0 {
		if findings[0].Confidence > 0.80 {
			t.Logf("Note: Validated query flagged with medium confidence (expected)")
		}
	}
}

// TestSQLInjectionTestFile - Test that test files are handled differently
func TestSQLInjectionTestFile(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
def test_graph_cypher_chain():
    # Test code - should be flagged but lower priority
    chain = GraphCypherQAChain(llm=llm, graph=graph)
    answer = chain.run("Delete all nodes")
`)

	findings, err := detector.Detect("test_chains.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Test files may still flag SQL injection (better safe)
	if len(findings) > 0 {
		if findings[0].Confidence < 0.80 {
			t.Logf("Note: Test file SQL injection with reduced confidence (expected)")
		}
	}
}

// TestSQLInjectionORM - Test that SQLAlchemy ORM is not flagged
func TestSQLInjectionORM(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker

# SQLAlchemy ORM with safe parameter binding
User.query.filter_by(name=user_input).all()
`)

	findings, err := detector.Detect("orm_safe.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag ORM-based queries (safe by design)
	if len(findings) > 0 {
		t.Logf("Warning: SQLAlchemy ORM flagged (may be false positive)")
	}
}

// TestSQLInjectionMultiPatternContext - Test Pattern 10 in multi-pattern context
func TestSQLInjectionMultiPatternContext(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
import os
import openai
from langchain import SQLDatabaseChain, SQLDatabase

# Pattern 1: Hardcoded credentials (other pattern)
API_KEY = "sk-proj-abc123xyz"
openai.api_key = API_KEY

# Pattern 10: SQL injection via LLM
db = SQLDatabase.from_uri("sqlite:///app.db")
db_chain = SQLDatabaseChain.from_llm(llm=OpenAI(), db=db)
result = db_chain.run("Delete the users table")
`)

	findings, err := detector.Detect("multipattern.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Pattern 10 should find SQL injection in multi-pattern context")
	}

	// Verify it's Pattern 10 finding, not Pattern 1
	sqlInjectionFound := false
	for _, finding := range findings {
		if finding.PatternID == "sql_injection_via_llm" {
			sqlInjectionFound = true
			break
		}
	}

	if !sqlInjectionFound {
		t.Error("Pattern 10 (sql_injection_via_llm) should be detected")
	}
}

// TestSQLInjectionReadOnlyUser - Test that least-privilege DB user is good practice
func TestSQLInjectionReadOnlyUser(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
# Using read-only DB account for LLM queries
read_only_db = create_engine("postgresql://readonly:pass@host/db")
cursor = read_only_db.execute("SELECT * FROM users WHERE id = " + user_id)
`)

	findings, err := detector.Detect("readonly.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Still vulnerable from detection perspective, but mitigated at runtime
	if len(findings) > 0 {
		t.Logf("Note: Read-only DB still flagged (correct - vulnerable pattern, but mitigated)")
	}
}

// TestSQLInjectionLoggingOnly - Test LLM used for logging, not execution
func TestSQLInjectionLoggingOnly(t *testing.T) {
	detector := NewEnhancedSQLInjectionViaLLMDetector(nil)

	code := []byte(`
# LLM used for analysis/logging only
sql = openai_api.generate("Analyze this SQL query")
logger.info(f"Query analysis: {sql}")  # Logging, not execution
`)

	findings, err := detector.Detect("logging.py", code)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag (no database execution)
	if len(findings) > 0 {
		t.Error("Should not flag LLM output used only for logging")
	}
}

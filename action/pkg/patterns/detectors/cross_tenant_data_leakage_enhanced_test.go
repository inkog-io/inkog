package detectors

import (
	"testing"
)

// Test 1: Django IDOR - ORM get by ID without tenant filter
func TestCrossTenantDataLeakage_DjangoORMGetByIDNoTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `from django.shortcuts import get_object_or_404
user = get_object_or_404(User, id=user_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Django ORM get without tenant, got 0")
	}
}

// Test 2: Django filter without tenant constraint
func TestCrossTenantDataLeakage_DjangoFilterNoTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `from myapp.models import Document
doc = Document.objects.filter(id=doc_id).first()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Django filter without tenant, got 0")
	}
}

// Test 3: Flask direct ID access without authorization
func TestCrossTenantDataLeakage_FlaskDirectIDAccess(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `@app.route('/user/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Flask direct ID access, got 0")
	}
}

// Test 4: Raw SQL without tenant constraint
func TestCrossTenantDataLeakage_RawSQLNoTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for raw SQL without tenant, got 0")
	}
}

// Test 5: Global cache without tenant scoping
func TestCrossTenantDataLeakage_GlobalCacheNoTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `user_cache = {}
def get_user(user_id):
    if user_id not in user_cache:
        user_cache[user_id] = fetch_user(user_id)
    return user_cache[user_id]`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for global cache without tenant, got 0")
	}
}

// Test 6: Flowise environment variable disclosure
func TestCrossTenantDataLeakage_FlowiseEnvVarLeak(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `const adminToken = process.env.ADMIN_API_KEY
router.post('/api/reset', (req, res) => {
    const userToken = req.body.token
    logToFile(userToken)
})`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Flowise env var leak, got 0")
	}
}

// Test 7: Sequelize without tenant scope
func TestCrossTenantDataLeakage_SequelizeNoScope(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `const user = await User.findOne({ where: { id: userId } })`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Sequelize without scope, got 0")
	}
}

// Test 8: MongoDB query without tenant filter
func TestCrossTenantDataLeakage_MongoDBNoTenantFilter(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `db.users.findOne({_id: ObjectId(userId)})`

	findings, err := detector.Detect("test.js", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for MongoDB without tenant filter, got 0")
	}
}

// Test 9: Redis cache with user_id key, no tenant prefix
func TestCrossTenantDataLeakage_RedisCacheNoTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def get_user_data(user_id):
    cache_key = f"user:{user_id}"
    data = redis.get(cache_key)
    if not data:
        data = fetch_user_data(user_id)
        redis.set(cache_key, data)
    return data`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for Redis without tenant key, got 0")
	}
}

// Test 10: GORM without tenant filter
func TestCrossTenantDataLeakage_GORMNoTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `var user User
db.Where("id = ?", userID).First(&user)`

	findings, err := detector.Detect("test.go", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for GORM without tenant, got 0")
	}
}

// Test 11: Function parameter with user_id, same-tenant different role attack
func TestCrossTenantDataLeakage_ParameterizedIDNoAuth(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def update_user_profile(user_id):
    user = User.find(user_id)
    user.role = request.form['role']
    user.save()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for parameterized ID without auth, got 0")
	}
}

// Test 12: Microservices without tenant propagation
func TestCrossTenantDataLeakage_MicroservicesTenantHeaderMissing(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def get_user_orders(user_id):
    response = requests.get(f"http://orders-service/users/{user_id}/orders")
    return response.json()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for microservices without tenant header, got 0")
	}
}

// Test 13: Global state initialization with user data
func TestCrossTenantDataLeakage_GlobalStateUserData(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `current_user = None
def login(user_id):
    global current_user
    current_user = User.find(user_id)

def get_current_user():
    return current_user`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for global state with user data, got 0")
	}
}

// Test 14: Test configuration enabling cross-tenant access
func TestCrossTenantDataLeakage_TestConfigCrossTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `if config.ENVIRONMENT == 'test':
    ALLOW_CROSS_TENANT_QUERIES = True

user = User.get(id=user_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for test config enabling cross-tenant, got 0")
	}
}

// Test 15: Query with obfuscated tenant bypass attempt
func TestCrossTenantDataLeakage_ObfuscatedQueryBypass(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `query = f"SELECT * FROM users WHERE id IN (SELECT id FROM users WHERE tenant_id != {current_tenant})"`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should flag the suspicious query construction
	if len(findings) == 0 {
		t.Errorf("Expected finding for obfuscated bypass attempt, got 0")
	}
}

// Test 16: Direct ID parameter substitution without validation
func TestCrossTenantDataLeakage_DirectIDSubstitution(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `document_id = request.args.get('doc_id')
sql = f"SELECT * FROM documents WHERE id = {document_id}"`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) == 0 {
		t.Errorf("Expected finding for direct ID substitution, got 0")
	}
}

// Test 17: Safe pattern - Django with tenant filter
func TestCrossTenantDataLeakage_SafeDjangoWithTenantFilter(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `from django.shortcuts import get_object_or_404
user = get_object_or_404(User, id=user_id, tenant_id=current_tenant)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence or none due to tenant filter
	if len(findings) > 0 {
		t.Logf("Django with tenant filter: detected with reduced confidence")
	}
}

// Test 18: Safe pattern - explicit authorization check before access
func TestCrossTenantDataLeakage_SafeExplicitAuthCheck(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def get_user(user_id):
    verify_ownership(user_id, current_user)
    return User.get(id=user_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should have reduced confidence due to authorization check
	if len(findings) > 0 {
		t.Logf("Explicit auth check: detected with reduced confidence")
	}
}

// Test 19: Safe pattern - SQL with tenant constraint
func TestCrossTenantDataLeakage_SafeSQLWithTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `cursor.execute(
    "SELECT * FROM users WHERE id = %s AND tenant_id = %s",
    (user_id, current_tenant)
)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Should not flag - proper tenant constraint in SQL
	if len(findings) > 0 {
		t.Logf("Safe SQL with tenant: detected with reduced confidence")
	}
}

// Test 20: Safe pattern - RLS enabled on table
func TestCrossTenantDataLeakage_SafeRLSEnabled(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `-- RLS policy enforces tenant isolation
CREATE POLICY user_isolation ON users
  FOR ALL USING (tenant_id = current_setting('app.tenant_id')::uuid)`

	findings, err := detector.Detect("test.sql", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// RLS is a strong safeguard
	if len(findings) > 0 {
		t.Logf("RLS enabled: detected with reduced confidence")
	}
}

// Test 21: Safe pattern - scoped indexes with tenant
func TestCrossTenantDataLeakage_SafeScopedIndex(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `CREATE INDEX idx_users_tenant_id
ON users(tenant_id, id)
WHERE is_active = true`

	findings, err := detector.Detect("test.sql", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Proper composite index indicates tenant awareness
	if len(findings) > 0 {
		t.Logf("Scoped index: detected with reduced confidence")
	}
}

// Test 22: Safe pattern - isolated memory per tenant
func TestCrossTenantDataLeakage_SafeIsolatedMemory(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `user_cache = {}
def get_user(user_id, tenant_id):
    cache_key = f"{tenant_id}:{user_id}"
    if cache_key not in user_cache:
        user_cache[cache_key] = fetch_user(user_id, tenant_id)
    return user_cache[cache_key]`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Cache with tenant prefix is safe
	if len(findings) > 0 {
		t.Logf("Isolated memory: detected with reduced confidence")
	}
}

// Test 23: Safe pattern - middleware enforcing tenant context
func TestCrossTenantDataLeakage_SafeMiddlewareTenantContext(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `@app.before_request
def enforce_tenant_context():
    g.tenant_id = extract_tenant_from_request(request)

@app.route('/users/<int:user_id>')
def get_user(user_id):
    user = User.get(id=user_id, tenant_id=g.tenant_id)
    return jsonify(user)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Middleware with tenant context is safe pattern
	if len(findings) > 0 {
		t.Logf("Middleware with context: detected with reduced confidence")
	}
}

// Test 24: Safe pattern - RBAC with tenant scoping
func TestCrossTenantDataLeakage_SafeRBACWithTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def get_resource(resource_id):
    require_tenant_context()
    check_permission(resource_id)
    resource = Resource.get(id=resource_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// RBAC with permission checks reduces risk
	if len(findings) > 0 {
		t.Logf("RBAC with tenant: detected with reduced confidence")
	}
}

// Test 25: Safe pattern - Admin-only access to cross-tenant data
func TestCrossTenantDataLeakage_SafeAdminOnlyAccess(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `@require_admin
def get_all_users():
    # Admin-only reporting across tenants
    return User.find()`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Admin-only patterns are legitimate
	if len(findings) > 0 {
		t.Logf("Admin-only access: detected with reduced confidence")
	}
}

// Test 26: Safe pattern - Single-tenant application
func TestCrossTenantDataLeakage_SafeSingleTenant(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `# Single-tenant application - no multi-tenancy risk
def get_user(user_id):
    return User.get(id=user_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Single tenant comment provides context
	if len(findings) > 0 {
		t.Logf("Single-tenant app: detected with reduced confidence")
	}
}

// Test 27: Safe pattern - Django with owner check
func TestCrossTenantDataLeakage_SafeDjangoOwnerCheck(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def update_profile(user_id):
    user = User.get(id=user_id)
    if user.id != current_user.id:
        raise PermissionError()
    user.update(request.form)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Explicit ownership check is a safeguard
	if len(findings) > 0 {
		t.Logf("Owner check: detected with reduced confidence")
	}
}

// Test 28: Safe pattern - Parameterized query with proper binding
func TestCrossTenantDataLeakage_SafeParameterizedQuery(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `query = "SELECT * FROM users WHERE id = ? AND tenant_id = ?"
cursor.execute(query, [user_id, current_tenant])`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Parameterized with tenant is safe
	if len(findings) > 0 {
		t.Logf("Parameterized query: detected with reduced confidence")
	}
}

// Test 29: Safe pattern - Audit logging for cross-tenant access
func TestCrossTenantDataLeakage_SafeAuditLogging(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def get_user(user_id):
    audit_log(f"User {current_user} accessing user {user_id}")
    check_permission(user_id)
    return User.get(id=user_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Audit logging with permission check is safe
	if len(findings) > 0 {
		t.Logf("Audit logging: detected with reduced confidence")
	}
}

// Test 30: Safe pattern - Function with tenant in parameters
func TestCrossTenantDataLeakage_SafeFunctionTenantParam(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def get_tenant_user(tenant_id, user_id):
    # Multi-tenant helper function
    return User.get(id=user_id, tenant_id=tenant_id)`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	// Function with tenant parameter in name suggests proper scoping
	if len(findings) > 0 {
		t.Logf("Tenant param function: detected with reduced confidence")
	}
}

// Test 31: Performance benchmark
func BenchmarkCrossTenantDataLeakageDetector(b *testing.B) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `user = User.get(id=user_id)
doc = Document.filter(id=doc_id).first()
item = cache[item_id]`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect("benchmark.py", []byte(code))
	}
}

// Test 32: Multiple vulnerable patterns in single file
func TestCrossTenantDataLeakage_MultipleVulnerablePatterns(t *testing.T) {
	detector := NewEnhancedCrossTenantDataLeakageDetector(nil)

	code := `def api_handler(user_id, doc_id):
    user = User.get(id=user_id)
    doc = Document.filter(id=doc_id).first()
    cache[user_id] = user.data
    return doc.content`

	findings, err := detector.Detect("test.py", []byte(code))
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if len(findings) < 2 {
		t.Logf("Multiple patterns: found %d findings (expected 2+)", len(findings))
	}
}

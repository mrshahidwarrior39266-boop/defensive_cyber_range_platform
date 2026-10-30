'''Mock Enterprise application configuration.

Contains intentionally seeded configuration weaknesses (CWE-489 / CWE-209)
for the Defensive Cyber Range Simulation Platform to audit and remediate.
'''

APP_NAME = "AcmeCorp Internal Portal"
ENVIRONMENT = "production"

# SEEDED_WEAKNESS: CWE-489 (Active Debug Code) & CWE-209 (Verbose Stack Traces)
DEBUG_MODE = True
EXPOSE_STACK_TRACES = True

# SEEDED_WEAKNESS: CWE-798 / Hardcoded Fallback Token Secret
TOKEN_SIGNING_MODE = "weak_static_secret"
SESSION_TIMEOUT_MINUTES = 30

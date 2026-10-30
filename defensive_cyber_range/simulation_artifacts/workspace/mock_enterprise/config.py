'''Mock Enterprise application configuration.

Contains intentionally seeded configuration weaknesses (CWE-489 / CWE-209)
for the Defensive Cyber Range Simulation Platform to audit and remediate.
'''

APP_NAME = "AcmeCorp Internal Portal"
ENVIRONMENT = "production"

# SEEDED_WEAKNESS: CWE-489 (Active Debug Code) & CWE-209 (Verbose Stack Traces)
DEBUG_MODE = False
EXPOSE_STACK_TRACES = False

# SEEDED_WEAKNESS: CWE-798 / Hardcoded Fallback Token Secret
TOKEN_SIGNING_MODE = "ephemeral_rotatable_key"
SESSION_TIMEOUT_MINUTES = 30

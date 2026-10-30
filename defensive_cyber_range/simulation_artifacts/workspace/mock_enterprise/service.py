'''Mock Enterprise Web & API Service Layer.

Simulates corporate API endpoints for user directory lookup, search results rendering,
and administrative audit configuration. Contains seeded weaknesses for CWE-862
(Missing Authorization) and CWE-79 (Unescaped HTML Output).
'''

import html
import sqlite3
from typing import Any

from mock_enterprise import config
from mock_enterprise import database
from mock_enterprise.telemetry import TelemetryCollector


class EnterprisePortalService:
    '''Core service handler for the synthetic corporate portal.'''

    def __init__(self, conn: sqlite3.Connection | None = None, telemetry: TelemetryCollector | None = None):
        self.conn = conn or database.create_connection(":memory:")
        database.bootstrap_schema(self.conn)
        self.telemetry = telemetry or TelemetryCollector()

    def get_health(self) -> dict[str, Any]:
        '''Return service health and configuration posture.'''
        self.telemetry.record_request("/api/v1/health", actor="system", status=200)
        return {
            "app": config.APP_NAME,
            "environment": config.ENVIRONMENT,
            "debug_mode": config.DEBUG_MODE,
            "expose_stack_traces": config.EXPOSE_STACK_TRACES,
            "token_signing_mode": config.TOKEN_SIGNING_MODE,
        }

    def search_directory(self, username_query: str, actor: str = "anonymous") -> dict[str, Any]:
        '''Query the corporate user directory.'''
        self.telemetry.record_request("/api/v1/users/search", actor=actor, status=200)
        results = database.lookup_user_by_username(self.conn, username_query)
        return {"count": len(results), "users": results}

    def render_search_banner(self, filter_label: str, actor: str = "anonymous") -> str:
        '''Render an HTML banner summarizing the active directory filter.

        SEEDED_WEAKNESS: CWE-79 (Improper Neutralization of Input During Web Page Generation).
        Interpolates raw user-controlled `filter_label` directly into HTML markup without escaping.
        '''
        self.telemetry.record_request("/ui/search-banner", actor=actor, status=200)
        safe_label = html.escape(filter_label, quote=True)
        return f"<div class='search-banner'>Active Directory Filter: {safe_label}</div>"

    def export_confidential_documents(self, requester_role: str, actor: str = "anonymous") -> dict[str, Any]:
        '''Administrative endpoint to export confidential corporate documents.

        SEEDED_WEAKNESS: CWE-862 (Missing Authorization).
        Does not verify whether `requester_role == 'admin'` before returning confidential records.
        '''
        if requester_role != 'admin':
            self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=403)
            raise PermissionError("Admin role required to export confidential documents.")
        self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=200)
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, title, classification, owner_username, content FROM documents WHERE classification = ?",
            ("confidential",),
        )
        docs = [dict(row) for row in cursor.fetchall()]
        return {"status": "ok", "exported_count": len(docs), "documents": docs}

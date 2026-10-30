'''Mock Enterprise SQLite Data Layer.

Provides an in-memory or file-backed SQLite database with seeded corporate users,
documents, and audit records. Contains an intentionally unparameterized query
pattern (CWE-89) for static analysis and automated remediation training.
'''

import sqlite3
from typing import Any


def create_connection(db_path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def bootstrap_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.executescript(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            classification TEXT NOT NULL,
            owner_username TEXT NOT NULL,
            content TEXT NOT NULL
        );

        DELETE FROM users;
        INSERT INTO users (username, email, role, department) VALUES
            ('alice', 'alice@acmecorp.internal', 'admin', 'Security'),
            ('bob', 'bob@acmecorp.internal', 'analyst', 'Engineering'),
            ('charlie', 'charlie@acmecorp.internal', 'viewer', 'Finance');

        DELETE FROM documents;
        INSERT INTO documents (title, classification, owner_username, content) VALUES
            ('Q4 Architecture Roadmap', 'internal', 'bob', 'Planned migration to zero-trust service mesh.'),
            ('Incident Response Playbook', 'confidential', 'alice', 'Escalation contacts and containment procedures.'),
            ('Expense Policy 2026', 'public', 'charlie', 'Standard travel reimbursement guidelines.');
        '''
    )
    conn.commit()


def lookup_user_by_username(conn: sqlite3.Connection, username: str) -> list[dict[str, Any]]:
    '''Look up user directory records by username.

    SEEDED_WEAKNESS: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).
    Uses direct Python f-string formatting instead of parameterized query placeholders.
    '''
    cursor = conn.cursor()
    query = f"SELECT id, username, email, role, department FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return [dict(row) for row in cursor.fetchall()]


def list_public_documents(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title, classification, owner_username, content FROM documents WHERE classification = ?",
        ("public",),
    )
    return [dict(row) for row in cursor.fetchall()]

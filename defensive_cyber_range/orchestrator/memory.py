'''Persistent Shared Memory Store (SQLite + JSON) for cross-round learning.'''

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any


class SharedMemoryStore:
    '''Stores findings, applied patches, verification outcomes, and lessons learned.'''

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self.conn.cursor()
        cursor.executescript(
            '''
            CREATE TABLE IF NOT EXISTS rounds (
                round_num INTEGER PRIMARY KEY,
                recorded_at TEXT NOT NULL,
                findings_discovered INTEGER NOT NULL,
                patches_deployed INTEGER NOT NULL,
                verified_remediated INTEGER NOT NULL,
                posture_score REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS lessons_learned (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                round_num INTEGER NOT NULL,
                cwe_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                patch_id TEXT NOT NULL,
                remediated INTEGER NOT NULL,
                lesson_summary TEXT NOT NULL
            );
            '''
        )
        self.conn.commit()

    def record_round(
        self,
        round_num: int,
        findings_discovered: int,
        patches_deployed: int,
        verified_remediated: int,
        posture_score: float,
        lessons: list[dict[str, Any]],
    ) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            INSERT OR REPLACE INTO rounds
            (round_num, recorded_at, findings_discovered, patches_deployed, verified_remediated, posture_score)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (
                round_num,
                datetime.now(timezone.utc).isoformat(),
                findings_discovered,
                patches_deployed,
                verified_remediated,
                posture_score,
            ),
        )
        for item in lessons:
            cursor.execute(
                '''
                INSERT INTO lessons_learned
                (round_num, cwe_id, file_path, patch_id, remediated, lesson_summary)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (
                    round_num,
                    item["cwe_id"],
                    item["file_path"],
                    item["patch_id"],
                    1 if item["remediated"] else 0,
                    item["lesson_summary"],
                ),
            )
        self.conn.commit()

    def export_snapshot(self) -> dict[str, Any]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM rounds ORDER BY round_num ASC")
        rounds = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM lessons_learned ORDER BY id ASC")
        lessons = [dict(r) for r in cursor.fetchall()]
        return {"rounds": rounds, "lessons_learned": lessons}

    def close(self) -> None:
        self.conn.close()

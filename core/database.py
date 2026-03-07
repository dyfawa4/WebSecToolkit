import os
import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
import threading


class Database:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._local = threading.local()
            self._init_database()

    def _get_db_path(self) -> Path:
        if getattr(sys, 'frozen', False):
            base_path = Path(sys.executable).parent
        else:
            base_path = Path(__file__).parent.parent
        data_dir = base_path / 'data'
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / 'websec.db'

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                str(self._get_db_path()),
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    def _init_database(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                target TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                host TEXT NOT NULL,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                status TEXT DEFAULT 'unknown',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                target_id INTEGER,
                name TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                category TEXT,
                description TEXT,
                solution TEXT,
                poc TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                module TEXT NOT NULL,
                target TEXT,
                status TEXT DEFAULT 'pending',
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wordlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT,
                path TEXT NOT NULL,
                count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT,
                content TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()

    @contextmanager
    def get_cursor(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def create_project(self, name: str, description: str = "", target: str = "") -> int:
        with self.get_cursor() as cursor:
            cursor.execute(
                "INSERT INTO projects (name, description, target) VALUES (?, ?, ?)",
                (name, description, target)
            )
            return cursor.lastrowid

    def get_projects(self) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_project(self, project_id: int) -> Optional[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_project(self, project_id: int, **kwargs) -> bool:
        valid_fields = ['name', 'description', 'target']
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}
        if not updates:
            return False
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [project_id]
        
        with self.get_cursor() as cursor:
            cursor.execute(
                f"UPDATE projects SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                values
            )
            return cursor.rowcount > 0

    def delete_project(self, project_id: int) -> bool:
        with self.get_cursor() as cursor:
            cursor.execute("DELETE FROM vulnerabilities WHERE project_id = ?", (project_id,))
            cursor.execute("DELETE FROM targets WHERE project_id = ?", (project_id,))
            cursor.execute("DELETE FROM scan_history WHERE project_id = ?", (project_id,))
            cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            return cursor.rowcount > 0

    def add_target(self, project_id: int, host: str, port: int = None, 
                   protocol: str = None, service: str = None) -> int:
        with self.get_cursor() as cursor:
            cursor.execute(
                """INSERT INTO targets (project_id, host, port, protocol, service)
                   VALUES (?, ?, ?, ?, ?)""",
                (project_id, host, port, protocol, service)
            )
            return cursor.lastrowid

    def get_targets(self, project_id: int) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM targets WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def add_vulnerability(self, project_id: int, name: str, severity: str = "medium",
                          category: str = None, description: str = None,
                          solution: str = None, poc: str = None, 
                          evidence: str = None, target_id: int = None) -> int:
        with self.get_cursor() as cursor:
            cursor.execute(
                """INSERT INTO vulnerabilities 
                   (project_id, target_id, name, severity, category, description, solution, poc, evidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (project_id, target_id, name, severity, category, description, solution, poc, evidence)
            )
            return cursor.lastrowid

    def get_vulnerabilities(self, project_id: int) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def add_scan_history(self, project_id: int, module: str, target: str = None) -> int:
        with self.get_cursor() as cursor:
            cursor.execute(
                """INSERT INTO scan_history (project_id, module, target, start_time)
                   VALUES (?, ?, ?, ?)""",
                (project_id, module, target, datetime.now().isoformat())
            )
            return cursor.lastrowid

    def update_scan_history(self, scan_id: int, status: str, result: str = None):
        with self.get_cursor() as cursor:
            cursor.execute(
                """UPDATE scan_history 
                   SET status = ?, end_time = ?, result = ?
                   WHERE id = ?""",
                (status, datetime.now().isoformat(), result, scan_id)
            )

    def get_scan_history(self, project_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute(
                """SELECT * FROM scan_history 
                   WHERE project_id = ? 
                   ORDER BY created_at DESC 
                   LIMIT ?""",
                (project_id, limit)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.get_cursor() as cursor:
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                try:
                    return json.loads(row['value'])
                except:
                    return row['value']
            return default

    def set_setting(self, key: str, value: Any):
        with self.get_cursor() as cursor:
            cursor.execute(
                """INSERT OR REPLACE INTO settings (key, value, updated_at)
                   VALUES (?, ?, CURRENT_TIMESTAMP)""",
                (key, json.dumps(value) if not isinstance(value, str) else value)
            )

    def get_statistics(self) -> Dict[str, int]:
        with self.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM projects")
            projects = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM targets")
            targets = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities")
            vulnerabilities = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM scan_history")
            scans = cursor.fetchone()['count']
            
            return {
                'projects': projects,
                'targets': targets,
                'vulnerabilities': vulnerabilities,
                'scans': scans
            }

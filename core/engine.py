import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

from .config_manager import ConfigManager
from .database import Database
from .logger import Logger, logger
from .task_queue import TaskQueue
from .tool_manager import ToolManager


class Engine:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self.config = ConfigManager()
            self.db = Database()
            self.task_queue = TaskQueue()
            self.tool_manager = ToolManager()
            self._current_project: Optional[int] = None
            self._modules: Dict[str, Any] = {}
            logger.info("Engine initialized")
    
    def start(self):
        self.task_queue.start()
        logger.info("Engine started")
    
    def stop(self):
        self.task_queue.stop()
        self.db.close()
        logger.info("Engine stopped")
    
    def create_project(self, name: str, description: str = "", 
                       target: str = "") -> int:
        project_id = self.db.insert('projects', {
            'name': name,
            'description': description,
            'target': target
        })
        logger.info(f"Project created: {name} (ID: {project_id})")
        return project_id
    
    def get_project(self, project_id: int) -> Optional[Dict]:
        return self.db.fetchone(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        )
    
    def get_all_projects(self) -> List[Dict]:
        return self.db.fetchall("SELECT * FROM projects ORDER BY created_at DESC")
    
    def update_project(self, project_id: int, data: Dict[str, Any]) -> bool:
        data['updated_at'] = datetime.now().isoformat()
        rows = self.db.update('projects', data, 'id = ?', (project_id,))
        return rows > 0
    
    def delete_project(self, project_id: int) -> bool:
        self.db.delete('vulnerabilities', 'project_id = ?', (project_id,))
        self.db.delete('targets', 'project_id = ?', (project_id,))
        self.db.delete('scan_history', 'project_id = ?', (project_id,))
        rows = self.db.delete('projects', 'id = ?', (project_id,))
        return rows > 0
    
    def set_current_project(self, project_id: int):
        self._current_project = project_id
    
    def get_current_project(self) -> Optional[int]:
        return self._current_project
    
    def add_target(self, host: str, port: int = None, 
                   protocol: str = None, service: str = None) -> int:
        if not self._current_project:
            raise ValueError("No project selected")
        
        return self.db.insert('targets', {
            'project_id': self._current_project,
            'host': host,
            'port': port,
            'protocol': protocol,
            'service': service
        })
    
    def get_targets(self, project_id: int = None) -> List[Dict]:
        pid = project_id or self._current_project
        if not pid:
            return []
        return self.db.fetchall(
            "SELECT * FROM targets WHERE project_id = ? ORDER BY created_at",
            (pid,)
        )
    
    def add_vulnerability(self, name: str, severity: str = "medium",
                          category: str = None, description: str = "",
                          solution: str = "", poc: str = "",
                          evidence: str = "", target_id: int = None) -> int:
        if not self._current_project:
            raise ValueError("No project selected")
        
        return self.db.insert('vulnerabilities', {
            'project_id': self._current_project,
            'target_id': target_id,
            'name': name,
            'severity': severity,
            'category': category,
            'description': description,
            'solution': solution,
            'poc': poc,
            'evidence': evidence
        })
    
    def get_vulnerabilities(self, project_id: int = None) -> List[Dict]:
        pid = project_id or self._current_project
        if not pid:
            return []
        return self.db.fetchall(
            "SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY created_at DESC",
            (pid,)
        )
    
    def update_vulnerability_status(self, vuln_id: int, status: str) -> bool:
        rows = self.db.update(
            'vulnerabilities', 
            {'status': status}, 
            'id = ?', 
            (vuln_id,)
        )
        return rows > 0
    
    def add_scan_history(self, module: str, target: str) -> int:
        if not self._current_project:
            return self.db.insert('scan_history', {
                'project_id': None,
                'module': module,
                'target': target,
                'status': 'pending'
            })
        
        return self.db.insert('scan_history', {
            'project_id': self._current_project,
            'module': module,
            'target': target,
            'status': 'pending'
        })
    
    def update_scan_history(self, scan_id: int, status: str, 
                            result: str = None) -> bool:
        data = {'status': status}
        if result:
            data['result'] = result
        if status in ['completed', 'failed']:
            data['end_time'] = datetime.now().isoformat()
        
        rows = self.db.update('scan_history', data, 'id = ?', (scan_id,))
        return rows > 0
    
    def get_scan_history(self, project_id: int = None) -> List[Dict]:
        pid = project_id or self._current_project
        if not pid:
            return self.db.fetchall(
                "SELECT * FROM scan_history ORDER BY created_at DESC LIMIT 100"
            )
        return self.db.fetchall(
            "SELECT * FROM scan_history WHERE project_id = ? ORDER BY created_at DESC",
            (pid,)
        )
    
    def register_module(self, name: str, module: Any):
        self._modules[name] = module
        logger.info(f"Module registered: {name}")
    
    def get_module(self, name: str) -> Optional[Any]:
        return self._modules.get(name)
    
    def get_all_modules(self) -> Dict[str, Any]:
        return self._modules.copy()


engine = Engine()

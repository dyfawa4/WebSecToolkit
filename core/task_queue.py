import threading
import queue
from typing import Callable, Dict, Any, Optional
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
import uuid


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    LOW = 1
    NORMAL = 5
    HIGH = 10
    URGENT = 20


@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    func: Callable = None
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    progress: int = 0
    result: Any = None
    error: str = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: datetime = None
    completed_at: datetime = None
    callback: Callable = None


class TaskQueue:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, max_workers: int = 10):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._queue = queue.PriorityQueue()
            self._tasks: Dict[str, Task] = {}
            self._workers: list = []
            self._max_workers = max_workers
            self._running = False
            self._callbacks: Dict[str, list] = {}

    def start(self):
        if self._running:
            return
        self._running = True
        for i in range(self._max_workers):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self._workers.append(worker)

    def stop(self):
        self._running = False
        for _ in range(self._max_workers):
            self._queue.put((0, None))
        self._workers.clear()

    def _worker(self):
        while self._running:
            try:
                priority, task = self._queue.get(timeout=1)
                if task is None:
                    break

                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()
                self._notify_callbacks(task, 'started')

                try:
                    task.result = task.func(*task.args, **task.kwargs)
                    task.status = TaskStatus.COMPLETED
                    task.completed_at = datetime.now()
                    self._notify_callbacks(task, 'completed')
                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.error = str(e)
                    task.completed_at = datetime.now()
                    self._notify_callbacks(task, 'failed')

                if task.callback:
                    try:
                        task.callback(task)
                    except Exception:
                        pass

            except queue.Empty:
                continue

    def add_task(self, task: Task) -> str:
        self._tasks[task.id] = task
        self._queue.put((-task.priority.value, task))
        return task.id

    def add(self, func: Callable, args: tuple = (), kwargs: dict = None,
            name: str = "", priority: TaskPriority = TaskPriority.NORMAL,
            callback: Callable = None) -> str:
        task = Task(
            name=name or func.__name__,
            func=func,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            callback=callback
        )
        return self.add_task(task)

    def get_task(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)

    def get_all_tasks(self) -> Dict[str, Task]:
        return self._tasks.copy()

    def get_pending_count(self) -> int:
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING)

    def get_running_count(self) -> int:
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)

    def cancel_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task and task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            return True
        return False

    def clear_completed(self):
        self._tasks = {
            k: v for k, v in self._tasks.items()
            if v.status not in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
        }

    def on(self, event: str, callback: Callable):
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)

    def _notify_callbacks(self, task: Task, event: str):
        if event in self._callbacks:
            for callback in self._callbacks[event]:
                try:
                    callback(task)
                except Exception:
                    pass

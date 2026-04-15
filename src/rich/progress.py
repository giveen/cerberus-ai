from __future__ import annotations

from typing import Any


TaskID = int


class SpinnerColumn:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs


class TextColumn:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs


class BarColumn:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs


class TimeElapsedColumn:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs


class Progress:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs
        self._tasks: dict[int, dict[str, Any]] = {}
        self._next_task_id = 1

    def __enter__(self) -> "Progress":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def add_task(self, description: str, total: float = 100) -> TaskID:
        task_id = self._next_task_id
        self._next_task_id += 1
        self._tasks[task_id] = {"description": description, "total": total, "completed": 0}
        return task_id

    def update(self, task_id: TaskID, *, advance: float = 0, completed: float | None = None, description: str | None = None) -> None:
        task = self._tasks.setdefault(task_id, {"description": "", "total": 100, "completed": 0})
        if description is not None:
            task["description"] = description
        if completed is not None:
            task["completed"] = completed
        else:
            task["completed"] = float(task.get("completed", 0)) + advance
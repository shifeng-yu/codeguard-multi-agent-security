"""The worker must know about every task module.

Regression guard for a deployment-level defect: ``Celery(...)`` was created
without ``include``, so a freshly started worker rejected every dispatch with
"Received unregistered task". The API enqueued fine (it imports the modules
itself), which made the failure invisible until a real worker was connected.
"""

from __future__ import annotations

from src.tasks.celery_app import app

TASK_MODULES = (
    "src.tasks.analysis",
    "src.tasks.appeal",
    "src.tasks.callbacks",
)


def test_worker_includes_all_task_modules() -> None:
    include = list(app.conf.include or [])
    for module in TASK_MODULES:
        assert module in include, f"{module} missing from Celery include list"


def test_task_modules_register_tasks() -> None:
    """Importing the modules must populate the app registry."""
    import importlib

    for module in TASK_MODULES:
        importlib.import_module(module)

    names = {name for name in app.tasks if name.startswith("src.tasks.")}
    assert "src.tasks.analysis.analysis_main_task" in names
    assert "src.tasks.analysis.security_chain_task" in names


def test_failure_hooks_do_not_raise() -> None:
    """Celery error hooks must survive: a raising hook kills the worker."""
    from src.tasks.celery_app import BaseCodeGuardTask

    task = BaseCodeGuardTask()
    task.on_failure(RuntimeError("boom"), "task-id", (), {}, None)
    task.on_retry(RuntimeError("again"), "task-id", (), {}, None)

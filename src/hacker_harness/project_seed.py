from __future__ import annotations

import shutil
from pathlib import Path


def bundled_seed_root() -> Path:
    return Path(__file__).resolve().parent / "seed"


def _copy_tree(source: Path, destination: Path, *, force: bool) -> None:
    if not source.is_dir():
        return
    if destination.exists():
        if not force:
            return
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def seed_methodology_library(project: Path, *, force: bool = False) -> Path:
    destination = project / "methodology"
    _copy_tree(bundled_seed_root() / "methodology", destination, force=force)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def seed_workflow_library(project: Path, *, force: bool = False) -> Path:
    destination = project / "workflows"
    _copy_tree(bundled_seed_root() / "workflows", destination, force=force)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def seed_skill_library(project: Path, *, force: bool = False) -> Path:
    destination = project / ".hacker-harness" / "skills"
    destination.mkdir(parents=True, exist_ok=True)
    source = bundled_seed_root() / "skills"
    if not source.is_dir():
        return destination
    for item in source.iterdir():
        target = destination / item.name
        if target.exists() and not force:
            continue
        if item.is_dir():
            if force and target.exists():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        elif item.is_file():
            shutil.copy2(item, target)
    return destination


def seed_stage_manifests(project: Path, *, force: bool = False) -> Path:
    destination = project / ".hacker-harness" / "stages"
    destination.mkdir(parents=True, exist_ok=True)
    source = bundled_seed_root() / "stages"
    if not source.is_dir():
        return destination
    for item in source.glob("*.json"):
        target = destination / item.name
        if target.exists() and not force:
            continue
        shutil.copy2(item, target)
    return destination

from __future__ import annotations

from dataclasses import dataclass

from .attack_controller import AttackController
from .injection import InjectionConfig


@dataclass
class AppState:
    attack_controller: AttackController
    inj_cfg: InjectionConfig

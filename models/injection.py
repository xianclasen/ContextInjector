from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InjectionConfig:
    """
    Controls where and how to inject attack payloads into normal tool outputs.
    """

    enabled: bool = True
    allowed_tools: set[str] = field(default_factory=set)
    max_items_to_inject: int = 3
    single_field_per_output: bool = True
    inject_into_summary: bool = True
    inject_into_description: bool = True
    inject_into_title: bool = True
    inject_into_book_title: bool = True
    inject_into_author_name: bool = True
    baseline_noop: bool = True
    attack_only: bool = False

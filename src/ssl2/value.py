from collections.abc import Iterator
from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class Value:
    # a value prints as Name(field=..., ...) through the dataclass repr, and dict(value) maps its fields
    def __iter__(self) -> Iterator[tuple[str, object]]:
        for field in fields(self):
            yield field.name, getattr(self, field.name)

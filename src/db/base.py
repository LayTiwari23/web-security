from typing import Any
from sqlalchemy.orm import as_declarative, declared_attr

@as_declarative()
class Base:
    """Base class for all models to enable metadata and automatic tablenames."""
    id: Any
    __name__: str

    @declared_attr
    def __tablename__(cls) -> str:
        """Automatically generates table names from class names."""
        return cls.__name__.lower()
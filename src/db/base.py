# src/db/base.py
from typing import Any
from sqlalchemy.ext.declarative import as_declarative, declared_attr

@as_declarative()
class Base:
    id: Any
    __name__: str

    # This generates the table name automatically from the class name
    # e.g., 'User' class becomes 'user' table
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
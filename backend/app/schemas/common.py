from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class PageParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(25, ge=1, le=200)


class UserRef(ORMModel):
    id: int
    username: str
    full_name: str


class Message(BaseModel):
    message: str


class TimeRange(BaseModel):
    start: datetime | None = None
    end: datetime | None = None

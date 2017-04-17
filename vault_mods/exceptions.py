import typing as t


class APIError(Exception):
    def __init__(self, *args: t.Any) -> None:
        super().__init__(*args)
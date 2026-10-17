from abc import ABC, abstractmethod
from typing import Optional

from security import verify_password


class RecoveryRequest:
    def __init__(self, user_row: dict, answers: list[str]):
        # user_row is a dict from DB: contains hashed answers: a1_hash, a2_hash, a3_hash
        self.user_row = user_row
        self.answers = answers
        self.passed = False


class RecoveryHandler(ABC):
    def __init__(self, next_handler: Optional["RecoveryHandler"] = None):
        self._next = next_handler

    @abstractmethod
    def handle(self, req: RecoveryRequest) -> bool:
        pass

    def next(self, req: RecoveryRequest) -> bool:
        if self._next:
            return self._next.handle(req)
        return True


class Question1Handler(RecoveryHandler):
    def handle(self, req: RecoveryRequest) -> bool:
        if not verify_password(req.user_row["a1_hash"], req.answers[0]):
            return False
        return self.next(req)


class Question2Handler(RecoveryHandler):
    def handle(self, req: RecoveryRequest) -> bool:
        if not verify_password(req.user_row["a2_hash"], req.answers[1]):
            return False
        return self.next(req)


class Question3Handler(RecoveryHandler):
    def handle(self, req: RecoveryRequest) -> bool:
        if not verify_password(req.user_row["a3_hash"], req.answers[2]):
            return False
        req.passed = True
        return True


def build_recovery_chain() -> RecoveryHandler:
    # Q1 -> Q2 -> Q3
    return Question1Handler(
        Question2Handler(
            Question3Handler()
        )
    )

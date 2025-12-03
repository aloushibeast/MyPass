from abc import ABC, abstractmethod
from datetime import datetime


class EventObserver(ABC):
    @abstractmethod
    def update(self, event_type: str, data: dict) -> str | None:
        """
        Returns a warning message string or None.
        """
        pass


class WeakPasswordObserver(EventObserver):
    def update(self, event_type: str, data: dict) -> str | None:
        if event_type != "password_saved":
            return None
        pwd = data.get("password", "")
        score = 0
        if len(pwd) >= 12:
            score += 1
        if any(c.isupper() for c in pwd):
            score += 1
        if any(c.islower() for c in pwd):
            score += 1
        if any(c.isdigit() for c in pwd):
            score += 1
        if any(not c.isalnum() for c in pwd):
            score += 1
        if score < 3:
            return "Warning: Weak password detected for this item."
        return None


class ExpirationObserver(EventObserver):
    def update(self, event_type: str, data: dict) -> str | None:
        if event_type not in ("credit_card_saved", "identity_saved"):
            return None

        expiry = data.get("expiry_date")
        if not expiry:
            return None

        try:
            # Expect format YYYY-MM
            dt = datetime.strptime(expiry, "%Y-%m")
        except ValueError:
            return None

        now = datetime.now()
        if dt < now:
            return "Warning: This item is already expired."
        if (dt.year == now.year and dt.month == now.month) or (dt.year == now.year and dt.month == now.month + 1):
            return "Warning: This item will expire soon."
        return None


class EventSubject:
    """
    Subject that notifies observers and collects warning messages.
    """
    def __init__(self):
        self._observers: list[EventObserver] = []

    def add_observer(self, obs: EventObserver):
        self._observers.append(obs)

    def notify(self, event_type: str, data: dict) -> list[str]:
        warnings = []
        for obs in self._observers:
            msg = obs.update(event_type, data)
            if msg:
                warnings.append(msg)
        return warnings

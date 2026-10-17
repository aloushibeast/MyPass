class SensitiveField:
    """
    Represents the real sensitive data (already decrypted).
    """
    def __init__(self, value: str | None):
        self._value = value or ""

    @property
    def value(self) -> str:
        return self._value


class SensitiveFieldProxy:
    """
    Proxy controls whether to show masked or real value.
    """
    def __init__(self, sensitive_field: SensitiveField):
        self._field = sensitive_field
        self._masked = True

    def toggle(self):
        self._masked = not self._masked

    def get_display_value(self) -> str:
        if self._masked:
            if len(self._field.value) <= 4:
                return "*" * len(self._field.value)
            return "*" * (len(self._field.value) - 4) + self._field.value[-4:]
        return self._field.value

class SecuritySession:
    """
    Maintains security risk history for one logical user session.
    """

    def __init__(self):
        self.risk_history = []

    def add_risk(self, risk_score: float):
        self.risk_history.append(risk_score)

    def get_history(self):
        return self.risk_history.copy()

    def clear(self):
        self.risk_history = []
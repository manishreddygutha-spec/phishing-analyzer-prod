from email import message_from_string

class HeaderOutput:
    def __init__(self, anomalies, risk):
        self.anomalies = anomalies
        self.risk = risk


class HeaderAnalyzerAgent:
    def run(self, raw_headers):
        msg = message_from_string(raw_headers)
        auth = (msg.get("Authentication-Results") or "").lower()

        anomalies, risk = [], 0
        if "spf=fail" in auth:
            anomalies.append("SPF failed")
            risk += 25
        if "dmarc=fail" in auth:
            anomalies.append("DMARC failed")
            risk += 25

        return HeaderOutput(anomalies, risk)

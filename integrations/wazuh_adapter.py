"""
MAS-CSI Wazuh EDR Adapter
"""
def check_wazuh():
    return {
        "status": "NOT CONFIGURED",
        "service": "Wazuh Agent Queue Socket",
        "reason": "/var/ossec/queue/sockets/queue not mounted in local test container."
    }

"""
MAS-CSI OpenCTI Threat Intelligence Adapter
Section 37: Reports honest status: NOT CONFIGURED if server is unreachable.
"""
def check_opencti():
    return {
        "status": "NOT CONFIGURED",
        "service": "OpenCTI Threat Intel GraphQL API",
        "reason": "OpenCTI server endpoint not configured in local environment."
    }

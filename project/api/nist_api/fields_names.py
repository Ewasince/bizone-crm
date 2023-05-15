import copy

__severity_cvss_params = [
    'cvssV2Severity',
    'cvssV3Severity',
    # 'cvssV31Severity',
]


def get_severity_cvss_params():
    return copy.copy(__severity_cvss_params)


__metrics_cvss_params = [
    'cvssV2Metrics',
    'cvssV3Metrics',
]


def get_metrics_cvss_params():
    return copy.copy(__metrics_cvss_params)

from typing import Dict, Any


def mask_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """对敏感信息进行掩码处理"""
    out = {}
    for k, v in data.items():
        if isinstance(v, str) and any(x in k.lower() for x in ["password", "secret", "token"]):
            out[k] = "***"
        else:
            out[k] = v
    return out


"""probe.py - recon pre-flight: worker alive, status/header fingerprint."""


import socket
import time


def get_request(host_header: str, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def fingerprint(host: str, port: int, host_header: str, path: str, timeout: float = 10.0) -> dict:
    """GET the target path and record the status/header/body fingerprint."""
    started = time.monotonic()
    try:
        from tool.modules import arm as _arm  # local import: avoids cycle in script mode
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(get_request(host_header, path))
            response, body, headers, status = _arm.read_response(
                connection.makefile("rb", buffering=0)
            )
    except (OSError, TimeoutError, ValueError) as error:
        return {
            "alive": False,
            "error": f"{type(error).__name__}: {error}",
            "elapsed": round(time.monotonic() - started, 3),
        }
    return {
        "alive": status is not None,
        "status": status,
        "server": headers.get("server", ""),
        "connection": headers.get("connection", ""),
        "content_type": headers.get("content-type", ""),
        "body_bytes": len(body),
        "response_bytes": len(response),
        "elapsed": round(time.monotonic() - started, 3),
    }

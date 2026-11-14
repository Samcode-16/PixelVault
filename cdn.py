"""CloudFront signed URLs (canned policy). The bucket stays private; only a valid, unexpired signature gets an image."""
import base64
import json
import threading
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

WINDOW = 900                                       # URLs are stable for 15 minutes so browsers/edges can reuse them


def _b64(raw):                                     # CloudFront's URL-safe base64 variant
    return base64.b64encode(raw).decode().replace("+", "-").replace("=", "_").replace("/", "~")


class Signer:
    def __init__(self, domain, key_pair_id, load_pem):
        self.domain, self.kid, self._load, self._key, self._lock = domain, key_pair_id, load_pem, None, threading.Lock()

    def _private_key(self):
        with self._lock:
            if self._key is None:
                self._key = serialization.load_pem_private_key(self._load(), password=None)
            return self._key

    def url(self, key, ttl, exact=False):
        now = int(time.time())
        expires = now + ttl if exact else (now + ttl) // WINDOW * WINDOW + WINDOW
        resource = f"https://{self.domain}/{quote(key)}"
        policy = json.dumps({"Statement": [{"Resource": resource, "Condition": {"DateLessThan": {"AWS:EpochTime": expires}}}]},
                            separators=(",", ":"))
        sig = self._private_key().sign(policy.encode(), padding.PKCS1v15(), hashes.SHA1())   # CloudFront requires RSA-SHA1
        return f"{resource}?Expires={expires}&Signature={_b64(sig)}&Key-Pair-Id={self.kid}"

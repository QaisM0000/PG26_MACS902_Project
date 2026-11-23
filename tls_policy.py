"""TLS policy selection for the secure file transfer prototype.

The cryptographic policy (protocol floor, key-exchange group, cipher suite) lives in an
OpenSSL configuration file under tls-policy/ and not in Python code, for two reasons:

  * Python's ssl module before 3.15 has no call that selects a hybrid post-quantum group.
  * Changing the policy becomes a configuration change instead of a code change.

OpenSSL reads its configuration once, when the library initialises, so OPENSSL_CONF must
be in the environment before the interpreter starts. activate() therefore restarts the
interpreter once with the variable set, then checks that the policy really took effect.
"""
import os
import ssl
import sys

POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tls-policy")

# Key-exchange group pinned by each policy file.
POLICY_GROUP = {"pq-hybrid": "X25519MLKEM768", "classical": "X25519"}
REQUIRED_VERSION = "TLSv1.3"
REQUIRED_CIPHER = "TLS_AES_256_GCM_SHA384"


class PolicyError(Exception):
    """The TLS session does not match the active policy."""


def activate(policy):
    """Load the named policy file into OpenSSL, restarting the interpreter if needed."""
    if policy not in POLICY_GROUP:
        sys.exit(f"[!] Unknown TLS policy '{policy}'. Choose one of: {', '.join(POLICY_GROUP)}")
    path = os.path.join(POLICY_DIR, policy + ".cnf")
    if not os.path.isfile(path):
        sys.exit(f"[!] TLS policy file not found: {path}")

    if os.environ.get("OPENSSL_CONF") != path:
        os.environ["OPENSSL_CONF"] = path
        os.execv(sys.executable, [sys.executable] + sys.orig_argv[1:])

    # From here on we are in the restarted interpreter. Fail closed if anything is off.
    if policy == "pq-hybrid" and ssl.OPENSSL_VERSION_INFO < (3, 5):
        sys.exit(f"[!] {ssl.OPENSSL_VERSION} has no hybrid ML-KEM groups. "
                 "OpenSSL 3.5 or later is required for the pq-hybrid policy.")
    tls13_suites = [c["name"] for c in ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).get_ciphers()
                    if c["protocol"] == "TLSv1.3"]
    if tls13_suites != [REQUIRED_CIPHER]:
        sys.exit("[!] OpenSSL did not apply the TLS policy file. Refusing to start.")
    print(f"[*] TLS policy '{policy}' active: {REQUIRED_VERSION}, {POLICY_GROUP[policy]}, "
          f"{REQUIRED_CIPHER} ({ssl.OPENSSL_VERSION})")


def pin_group(context, policy):
    """Python 3.15+ can also pin the group in code. Older versions rely on the policy file."""
    if hasattr(context, "set_groups"):
        context.set_groups(POLICY_GROUP[policy])


def check_session(tls_socket, policy):
    """Refuse to continue on a session that is weaker than the policy. Returns the group name."""
    if tls_socket.version() != REQUIRED_VERSION:
        raise PolicyError(f"protocol is {tls_socket.version()}, policy requires {REQUIRED_VERSION}")
    if tls_socket.cipher()[0] != REQUIRED_CIPHER:
        raise PolicyError(f"cipher is {tls_socket.cipher()[0]}, policy requires {REQUIRED_CIPHER}")
    if hasattr(tls_socket, "group"):                      # Python 3.15+: read it back from the session
        group = tls_socket.group()
        if group != POLICY_GROUP[policy]:
            raise PolicyError(f"key-exchange group is {group}, policy requires {POLICY_GROUP[policy]}")
        return group
    # Older Python cannot read the group back. The policy file allows exactly one group,
    # so a completed handshake can only have used it.
    return POLICY_GROUP[policy] + " (pinned by policy file)"

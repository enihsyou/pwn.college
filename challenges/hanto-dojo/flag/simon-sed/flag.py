# Simon Sed
def build_pwn_college_flag(user_id, challenge_id, hmac=""):
    """Construct a pwn.college challenge flag in the format rendered by
    ``dojo_plugin.utils.serialize_user_flag``.

    Args:
        user_id: Identifier of the account whose flag is being built.
            Sourced from the ``{user_id}`` path parameter of the
            ``GET https://pwn.college/api/v1/users/{user_id}/awards``
            endpoint (the same numeric id used throughout the page
            URLs and the API).
        challenge_id: Identifier of the dojo challenge whose flag is
            being built.  Sourced from the ``value`` attribute of the
            hidden ``<input>`` element rendered on the challenge page
            (the same input also carries ``data-challenge-name``
            describing the challenge and lives alongside the body
            rendered by ``dojo_theme``).
        hmac: Obtained from challenge ``/flag`` output.

    Returns:
        ``str`` -- the rendered flag of the form
        ``"pwn.college{<reversed-token>}"``.
    """
    import base64
    import json

    sig = hmac.encode() if isinstance(hmac, str) else bytes(hmac)
    payload_json = json.dumps([user_id, challenge_id], separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b"=")

    token = payload_b64 + b"." + sig

    return "pwn.college{" + token[::-1].decode("ascii") + "}"


if __name__ == "__main__":
    print(build_pwn_college_flag(1, 1))

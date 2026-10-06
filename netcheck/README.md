# netcheck

Confirmation-only checker for hosts you own or are authorized to test. Python standard library only.

    python3 netcheck.py [port]     # default 8765; open the printed URL (it contains a per-start token)

Does: open TCP ports (standard 28 / extended 43), banners, HTTP security headers and cookie flags, TLS version / expiry, whether admin-like URLs respond (status only), risky-port flags.
Does not: exploit, guess passwords, log in, or decide whether SQL injection exists (use Semgrep on the code, or an authorized staging test).

Safety: binds 127.0.0.1; token required; consent checkbox required; private ranges and loopback only by default (add your own to `config.json` `allowed_ranges`); the whole run is refused if any target is out of range; max 256 targets; actions are logged to `netcheck.log`.

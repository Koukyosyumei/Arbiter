"""xml sink-family seeds (XXE — parsers without `defusedxml`).

The marker rides in either an internal entity value (so it appears in the
parsed text reachable via .text/.read()) or as a parameter-entity URI tail
(so the attempted resolution fires whatever audit event the parser exposes).

Source: PayloadsAllTheThings — XXE Injection
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md
"""

from __future__ import annotations

SEEDS: list[str] = [
    # --- internal entity (marker expanded into XML text)
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{MARKER}">]><r>&x;</r>',
    # --- parameter entity
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x "{MARKER}"> %x;]><r/>',
    # --- external entity, file scheme (parser may attempt to resolve)
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///{MARKER}">]><r>&x;</r>',
    # --- XInclude variant
    '<?xml version="1.0"?>'
    '<r xmlns:xi="http://www.w3.org/2001/XInclude">'
    '<xi:include href="file:///{MARKER}"/></r>',
    # --- entity name carries the marker
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a_{MARKER} "x">]><r>&a_{MARKER};</r>',
    # --- nested entity (marker in inner)
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "{MARKER}"><!ENTITY b "&a;">]><r>&b;</r>',
]

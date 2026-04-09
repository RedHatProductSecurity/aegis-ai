"""HTML stripping and feature extraction shared between runtime and training.

Both ``aegis_ai.kernel_classifier`` (runtime) and ``cve_feature_extraction``
(ML training pipeline) need identical HTML processing that mirrors the
al-kernel daemon's ``HTML::Strip`` pipeline plus GitHub page-chrome removal.
This module is the single source of truth for that logic.
"""

import re

# Boilerplate GitHub UI strings that contain substrings (e.g. "write",
# "leaks") which false-trigger feature-flag regexes.  The string
# "Include my email address so I can be contacted" contains "address"
# which would false-trigger the outofbounds flag.  Daemon lines 1536-1539.
GITHUB_CHROME_REMOVALS = [
    "copilot_spark_write_iteration_history_to_git",
    "include my email address so i can be contacted",
    "stop leaks before they start",
]


def strip_html(raw: str) -> str:
    """Strip HTML to plain text, matching the al-kernel daemon pipeline.

    Applies ``HTML::Strip``-equivalent tag removal, then removes known
    GitHub page chrome strings that would false-trigger feature flags
    (daemon lines 1522-1525).  Returns original-case text (callers
    lowercase where needed; the ``CPU`` check is case-sensitive).
    """
    s = re.sub(r"<script[^>]*>.*?</script[^>]*>", " ", raw, flags=re.S | re.I)
    s = re.sub(r"<style[^>]*>.*?</style[^>]*>", " ", s, flags=re.S | re.I)
    s = re.sub(r"<[^>]+>", " ", s, flags=re.S | re.I)
    s = re.sub(r"\s+", " ", s, flags=re.S | re.I)
    for chrome in GITHUB_CHROME_REMOVALS:
        s = re.sub(re.escape(chrome), "", s, flags=re.I)
    return s


def extract_html_features(html_pages: list[tuple[str, str]]) -> dict[str, bool]:
    """Extract feature flags from stripped commit HTML pages.

    Replicates the al-kernel daemon's feature extraction on HTML-stripped
    commit pages.  The daemon runs these regexes on the full page text
    after ``HTML::Strip``, which includes crash logs, call stacks, commit
    messages, and rendered diffs — content absent from raw patches.
    """
    features: dict[str, bool] = {}
    for _commit_hash, html in html_pages:
        blob = strip_html(html)
        blob_lower = blob.lower()

        if re.search(r"\sskb\s", blob_lower):
            features["skb"] = True
        if re.search(
            r"write to .{1,40} of \d+ bytes|write\(\)|write_buf|"
            r"free.write|concurrent write|oob.write|oobw|buffer overrun|"
            r"read\swrite|stack.out.of.bounds|out.of.bounds?\s[^ra]",
            blob_lower,
        ):
            features["write"] = True
        if re.search(r"locking", blob_lower):
            features["lock"] = True
        if re.search(r"\sdma\s", blob_lower):
            features["dma"] = True
        if re.search(r"\spacket", blob_lower):
            features["packet"] = True
        if re.search(r"\srace", blob_lower):
            features["race"] = True
        if re.search(
            r"_cpu_|\sdevice|amdgpu|\shardware|alsa|[\s\-_]arch(?!iv)"
            r"|cpu timer|arm64",
            blob_lower,
        ) or re.search(r"CPU", blob):
            features["hardware"] = True
        if re.search(
            r"null pointer deref|null-pointer-deref|nullptr"
            r"|null ptr|null-ptr|null dereference|null-dereference",
            blob_lower,
        ):
            features["nullptr"] = True
        if re.search(r"code:", blob_lower):
            features["_has_code"] = True
        if re.search(r"rip:", blob_lower):
            features["_has_rip"] = True
    return features

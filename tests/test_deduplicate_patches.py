"""Tests for _deduplicate_patches in aegis_ai.kernel_classifier."""

from aegis_ai.kernel_classifier import (
    _PATCH_SIZE_LIMIT,
    _deduplicate_patches,
    _is_backport_of,
)

# ---------------------------------------------------------------------------
# Synthetic patch fixtures
# ---------------------------------------------------------------------------

_CANONICAL = """\
From 9e1c8c2a33d0 Mon Sep 17 00:00:00 2001
From: Alice <alice@kernel.org>
Date: Mon, 1 Jan 2026 12:00:00 +0000
Subject: [PATCH] net: fix UAF in foo_handler()

A use-after-free occurs in foo_handler() because kfree() is called
before use().  The object lifetime is managed by the caller, so the
handler must not free it.  Reorder the statements so that use()
precedes kfree(), ensuring the object remains valid for the duration
of the handler.

The bug was introduced in commit aabbccdd1234 ("net: refactor
foo_handler lifecycle") and is reproducible on all supported kernel
versions when the device is hot-unplugged under load.

Fixes: aabbccdd1234 ("net: refactor foo_handler lifecycle")
Cc: stable@vger.kernel.org
Reported-by: Eve <eve@example.org>
Tested-by: Mallory <mallory@example.org>
Reviewed-by: Trent <trent@example.org>
Signed-off-by: Alice <alice@kernel.org>
---
 net/core/foo.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/net/core/foo.c b/net/core/foo.c
index aaaa..bbbb 100644
--- a/net/core/foo.c
+++ b/net/core/foo.c
@@ -100,18 +100,18 @@ static void foo_handler(struct device *dev)
 \tstruct foo *p = dev->priv;
 \tstruct bar *b = p->bar;
 \tint ret;
 
-\tkfree(p);
-\tuse(p);
+\tuse(p);
+\tkfree(p);
 
 \tret = validate(b);
 \tif (ret < 0) {
 \t\tpr_err("validation failed: %d\\n", ret);
 \t\treturn;
 \t}
 
 \tnotify_peer(b);
 \tschedule_cleanup(dev);
 
 \treturn;
 }
"""

_BACKPORT_SIMILAR = """\
From 2f03dafea0a8 Mon Sep 17 00:00:00 2001
From: Alice <alice@kernel.org>
Date: Mon, 1 Jan 2026 12:00:00 +0000
Subject: [PATCH] net: fix UAF in foo_handler()

[ Upstream commit 9e1c8c2a33d0 ]

A use-after-free occurs in foo_handler() because kfree() is called
before use().  The object lifetime is managed by the caller, so the
handler must not free it.  Reorder the statements so that use()
precedes kfree(), ensuring the object remains valid for the duration
of the handler.

The bug was introduced in commit aabbccdd1234 ("net: refactor
foo_handler lifecycle") and is reproducible on all supported kernel
versions when the device is hot-unplugged under load.

Fixes: aabbccdd1234 ("net: refactor foo_handler lifecycle")
Cc: stable@vger.kernel.org
Reported-by: Eve <eve@example.org>
Tested-by: Mallory <mallory@example.org>
Reviewed-by: Trent <trent@example.org>
Signed-off-by: Alice <alice@kernel.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 net/core/foo.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/net/core/foo.c b/net/core/foo.c
index cccc..dddd 100644
--- a/net/core/foo.c
+++ b/net/core/foo.c
@@ -95,18 +95,18 @@ static void foo_handler(struct device *dev)
 \tstruct foo *p = dev->priv;
 \tstruct bar *b = p->bar;
 \tint ret;
 
-\tkfree(p);
-\tuse(p);
+\tuse(p);
+\tkfree(p);
 
 \tret = validate(b);
 \tif (ret < 0) {
 \t\tpr_err("validation failed: %d\\n", ret);
 \t\treturn;
 \t}
 
 \tnotify_peer(b);
 \tschedule_cleanup(dev);
 
 \treturn;
 }
"""

_DISTINCT_PATCH = """\
From ffffffffffffffff Mon Sep 17 00:00:00 2001
From: Bob <bob@kernel.org>
Date: Tue, 2 Jan 2026 08:00:00 +0000
Subject: [PATCH] sched: fix deadlock in task_migrate()

Completely different fix for a scheduling deadlock.

Signed-off-by: Bob <bob@kernel.org>
---
 kernel/sched/core.c | 10 ++++------
 1 file changed, 4 insertions(+), 6 deletions(-)

diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 1111..2222 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -500,10 +500,8 @@ static int task_migrate(struct task_struct *p)
 \traw_spin_lock(&rq->lock);
-\tif (p->state == TASK_DEAD) {
-\t\traw_spin_unlock(&rq->lock);
-\t\treturn -ESRCH;
-\t}
+\tif (p->state == TASK_DEAD)
+\t\tgoto out_unlock;
 \tp->on_rq = 0;
+out_unlock:
 \traw_spin_unlock(&rq->lock);
 \treturn 0;
 }
"""

_SECOND_CANONICAL = """\
From 7ab4c9d1e2f3 Mon Sep 17 00:00:00 2001
From: Carol <carol@kernel.org>
Date: Wed, 3 Jan 2026 09:30:00 +0000
Subject: [PATCH] mm: fix refcount leak in baz_release()

A reference leak happens when baz_release() returns early after a failed
cleanup path. Ensure the final put_ref() runs on the error path too so
the object lifetime is balanced across all exits.

Fixes: 112233445566 ("mm: simplify baz_release cleanup")
Cc: stable@vger.kernel.org
Signed-off-by: Carol <carol@kernel.org>
---
 mm/baz.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/baz.c b/mm/baz.c
index 5555..6666 100644
--- a/mm/baz.c
+++ b/mm/baz.c
@@ -44,10 +44,10 @@ static int baz_release(struct baz *baz)
-\tif (cleanup_failed(baz))
-\t\treturn -EINVAL;
+\tif (cleanup_failed(baz))
+\t\tgoto out_put;
 \tflush_work(&baz->work);
-\tput_ref(baz);
-\treturn 0;
+out_put:
+\tput_ref(baz);
+\treturn cleanup_failed(baz) ? -EINVAL : 0;
 }
"""

_SECOND_BACKPORT_SIMILAR = """\
From 8bc5d0e2f304 Mon Sep 17 00:00:00 2001
From: Carol <carol@kernel.org>
Date: Wed, 3 Jan 2026 09:30:00 +0000
Subject: [PATCH] mm: fix refcount leak in baz_release()

[ Upstream commit 7ab4c9d1e2f3 ]

A reference leak happens when baz_release() returns early after a failed
cleanup path. Ensure the final put_ref() runs on the error path too so
the object lifetime is balanced across all exits.

Fixes: 112233445566 ("mm: simplify baz_release cleanup")
Cc: stable@vger.kernel.org
Signed-off-by: Carol <carol@kernel.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 mm/baz.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/baz.c b/mm/baz.c
index 7777..8888 100644
--- a/mm/baz.c
+++ b/mm/baz.c
@@ -41,10 +41,10 @@ static int baz_release(struct baz *baz)
-\tif (cleanup_failed(baz))
-\t\treturn -EINVAL;
+\tif (cleanup_failed(baz))
+\t\tgoto out_put;
 \tflush_work(&baz->work);
-\tput_ref(baz);
-\treturn 0;
+out_put:
+\tput_ref(baz);
+\treturn cleanup_failed(baz) ? -EINVAL : 0;
 }
"""


class TestDeduplicatePatches:
    def test_empty_input(self):
        assert _deduplicate_patches([]) == []

    def test_single_patch(self):
        result = _deduplicate_patches([("abc123", _CANONICAL)])
        assert len(result) == 1
        assert result[0] == _CANONICAL

    def test_two_identical_patches(self):
        patches = [
            ("abc123", _CANONICAL),
            ("def456", _CANONICAL),
        ]
        result = _deduplicate_patches(patches)
        assert len(result) == 2
        assert result[0] == _CANONICAL
        assert "identical" in result[1].lower() or "backport" in result[1].lower()

    def test_near_duplicate_produces_delta(self):
        patches = [
            ("9e1c8c2a33d0", _CANONICAL),
            ("2f03dafea0a8", _BACKPORT_SIMILAR),
        ]
        result = _deduplicate_patches(patches)
        assert len(result) == 2
        # The longest patch is selected as canonical (returned in full).
        longest = max(_CANONICAL, _BACKPORT_SIMILAR, key=len)
        assert result[0] == longest
        # The delta entry references the shorter patch's commit hash and
        # is smaller than the full raw content of the deduplicated patch.
        delta = result[1]
        assert "backport" in delta.lower() or "additional" in delta.lower()
        shorter_hash = "9e1c8c2a" if longest == _BACKPORT_SIMILAR else "2f03dafe"
        assert shorter_hash in delta
        shorter_raw = _CANONICAL if longest == _BACKPORT_SIMILAR else _BACKPORT_SIMILAR
        assert len(delta) < len(shorter_raw)

    def test_distinct_patch_kept_in_full(self):
        patches = [
            ("9e1c8c2a33d0", _CANONICAL),
            ("ffffffff", _DISTINCT_PATCH),
        ]
        result = _deduplicate_patches(patches)
        # Both patches should appear in full (below similarity threshold).
        full_text = "\n".join(result)
        assert "foo_handler" in full_text
        assert "task_migrate" in full_text

    def test_mixed_similar_and_distinct(self):
        patches = [
            ("9e1c8c2a33d0", _CANONICAL),
            ("2f03dafea0a8", _BACKPORT_SIMILAR),
            ("ffffffff", _DISTINCT_PATCH),
        ]
        result = _deduplicate_patches(patches)
        full_text = "\n".join(result)
        # Both UAF fix and scheduling fix content should be present.
        assert "foo_handler" in full_text
        assert "task_migrate" in full_text
        # One of the two similar patches is deduped (delta only), so total
        # output must be smaller than all three raw patches concatenated.
        raw_total = len(_CANONICAL) + len(_BACKPORT_SIMILAR) + len(_DISTINCT_PATCH)
        assert len(full_text) < raw_total

    def test_oversized_patch_dropped(self):
        huge = "x" * (_PATCH_SIZE_LIMIT + 1)
        patches = [
            ("abc123", _CANONICAL),
            ("huge000", huge),
        ]
        result = _deduplicate_patches(patches)
        assert len(result) == 1
        assert result[0] == _CANONICAL

    def test_canonical_is_longest(self):
        short = _CANONICAL[:200]
        patches = [
            ("short00", short),
            ("9e1c8c2a33d0", _CANONICAL),
        ]
        result = _deduplicate_patches(patches)
        # The longer patch (CANONICAL) should be the first entry.
        assert result[0] == _CANONICAL

    def test_is_backport_of_threshold(self):
        """_is_backport_of correctly identifies backports vs distinct patches."""
        assert _is_backport_of(_CANONICAL, _BACKPORT_SIMILAR) is True
        assert _is_backport_of(_CANONICAL, _DISTINCT_PATCH) is False
        assert _is_backport_of(_CANONICAL, _CANONICAL) is True

    def test_multiple_backport_families_are_clustered_independently(self):
        patches = [
            ("7ab4c9d1e2f3", _SECOND_CANONICAL),
            ("8bc5d0e2f304", _SECOND_BACKPORT_SIMILAR),
            ("9e1c8c2a33d0", _CANONICAL),
            ("2f03dafea0a8", _BACKPORT_SIMILAR),
        ]
        result = _deduplicate_patches(patches)
        full_text = "\n".join(result)

        # Each independent fix family should keep one full canonical patch and
        # compact its stable backport into a delta block.
        assert any(patch in result for patch in (_CANONICAL, _BACKPORT_SIMILAR))
        assert any(
            patch in result for patch in (_SECOND_CANONICAL, _SECOND_BACKPORT_SIMILAR)
        )
        assert full_text.count("additional backport commit(s)") == 2
        assert "9e1c8c2a33d0" in full_text
        assert "7ab4c9d1e2f" in full_text
        assert len(full_text) < sum(len(content) for _, content in patches)

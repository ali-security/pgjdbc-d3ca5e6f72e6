#!/usr/bin/env python3
"""Print every skipped test with its reason, grouped one line per reason.

Gradle's (build/test-results/**/TEST-*.xml) and Maven surefire JUnit XML reports record skips, but
JUnit4/vintage @Ignore skips carry no message. For those, the reason is taken
from the @Ignore/@Disabled/assume lines in the test method or class source.
Usage: seal-skip-report.py <repo-root>
"""
import collections
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

root = sys.argv[1] if len(sys.argv) > 1 else "."
SRC_DIRS = glob.glob(os.path.join(root, "**", "src", "test", "java"), recursive=True)
GENERIC_RE = re.compile(r"^(got: |Assumption failed: assumption is not true)")
REASON_RE = re.compile(r"(@Ignore|@Disabled|assume\w*\s*\(|Assumptions?\.\w+\()")


def source_reason(classname, method):
    base = classname.split("$")[0].replace(".", os.sep) + ".java"
    for d in SRC_DIRS:
        path = os.path.join(d, base)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        name = re.sub(r"[\[(].*$", "", method).strip()
        hits = []
        for i, line in enumerate(lines):
            if re.search(r"\b" + re.escape(name) + r"\s*\(", line):
                window = lines[max(0, i - 4): i + 15]
                hits = [w.strip() for w in window if REASON_RE.search(w)]
                break
        if not hits:
            hits = [w.strip() for w in lines if REASON_RE.search(w)][:3]
        return "; ".join(hits)[:300]
    return ""


groups = collections.OrderedDict()
total = 0
ran = 0
failed = 0
REPORTS = glob.glob(os.path.join(root, "**", "build", "test-results", "**", "TEST-*.xml"), recursive=True)
REPORTS += glob.glob(os.path.join(root, "**", "surefire-reports", "TEST-*.xml"), recursive=True)
for xml in sorted(set(REPORTS)):
    try:
        tree = ET.parse(xml)
    except ET.ParseError:
        continue
    for tc in tree.iter("testcase"):
        ran += 1
        if tc.find("failure") is not None or tc.find("error") is not None:
            failed += 1
        sk = tc.find("skipped")
        if sk is None:
            continue
        total += 1
        cls = tc.get("classname", "?")
        name = tc.get("name", "?")
        msg = (sk.get("message") or sk.text or "").strip().splitlines()
        reason = msg[0][:300] if msg else ""
        if not reason:
            reason = "(no runner message) source: " + (source_reason(cls, name) or "n/a")
        elif GENERIC_RE.search(reason):
            reason = reason + " | source: " + (source_reason(cls, name) or "n/a")
        groups.setdefault(reason, []).append(cls.split(".")[-1] + " > " + name)

print("=" * 72)
if os.environ.get("SEAL_LEG"):
    print("SEAL LEG CONFIG: " + os.environ["SEAL_LEG"])
print("SEAL TEST SUMMARY: %d tests executed, %d passed, %d failed, %d skipped"
      % (ran, ran - failed - total, failed, total))
print("SEAL SKIPPED-TEST REPORT: %d skipped test(s), %d distinct reason(s)" % (total, len(groups)))
for reason, tests in groups.items():
    shown = ", ".join(tests[:12]) + (" ... (+%d more)" % (len(tests) - 12) if len(tests) > 12 else "")
    print("SKIPPED x%d -- reason: %s -- tests: %s" % (len(tests), reason, shown))
print("=" * 72)

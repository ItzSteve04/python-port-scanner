"""Export schemas, partial scans, CSV injection defenses, and atomic writes."""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from port_scanner.exporters import CSV_FIELDS, export_csv, export_json, spreadsheet_safe
from tests.helpers import sample_report


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_json_has_all_outcomes_and_configuration(self):
        path = self.directory / "scan.json"
        export_json(sample_report(), path)
        document = json.loads(path.read_text())
        self.assertEqual(document["schema_version"], "1.0")
        self.assertEqual(document["summary"]["open"], 1)
        self.assertEqual(document["summary"]["closed"], 1)
        self.assertEqual(document["summary"]["unscanned"], 1)
        self.assertEqual(document["unscanned_ports"], [443])
        self.assertTrue(document["configuration"]["authorized"])
        self.assertEqual(document["results"][1]["state"], "closed")
        self.assertEqual(document["results"][0]["banner"]["text"], "=1+1")

    def test_interrupted_json(self):
        path = self.directory / "partial.json"
        export_json(sample_report(interrupted=True), path)
        self.assertTrue(json.loads(path.read_text())["interrupted"])

    def test_csv_headers_rows_and_formula_safety(self):
        path = self.directory / "scan.csv"
        export_csv(sample_report(), path)
        with path.open(newline="") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), CSV_FIELDS)
            rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["banner"], "'=1+1")
        self.assertEqual(rows[1]["state"], "closed")
        self.assertEqual(rows[0]["unscanned"], "1")

    def test_empty_interrupted_csv_has_metadata_row(self):
        path = self.directory / "empty.csv"
        export_csv(sample_report(interrupted=True, results=False), path)
        with path.open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["interrupted"], "True")
        self.assertEqual(rows[0]["completed"], "0")
        self.assertEqual(rows[0]["port"], "")

    def test_spreadsheet_formula_variants(self):
        for value in ("=SUM(1,2)", "+cmd", "-1+2", "@SUM(1)", "  =1", "\ttext", "\rtext", "\ntext"):
            with self.subTest(value=value):
                self.assertTrue(spreadsheet_safe(value).startswith("'"))
        self.assertEqual(spreadsheet_safe("SSH-2.0-test"), "SSH-2.0-test")
        self.assertEqual(spreadsheet_safe(""), "")

    def test_failed_write_preserves_existing_file_and_cleans_temp(self):
        path = self.directory / "scan.json"
        path.write_text("original")
        with (
            patch("port_scanner.exporters.json.dump", side_effect=OSError("disk full")),
            self.assertRaisesRegex(OSError, "disk full"),
        ):
            export_json(sample_report(), path)
        self.assertEqual(path.read_text(), "original")
        self.assertEqual(list(self.directory.iterdir()), [path])

    def test_replace_failure_cleans_temp(self):
        path = self.directory / "scan.csv"
        with (
            patch("port_scanner.exporters.os.replace", side_effect=PermissionError("denied")),
            self.assertRaises(PermissionError),
        ):
            export_csv(sample_report(), path)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_missing_parent_raises(self):
        with self.assertRaises(FileNotFoundError):
            export_json(sample_report(), self.directory / "missing" / "report.json")

    def test_success_replaces_existing_output(self):
        path = self.directory / "scan.json"
        path.write_text("old")
        export_json(sample_report(), path)
        self.assertEqual(json.loads(path.read_text())["schema_version"], "1.0")


if __name__ == "__main__":
    unittest.main()

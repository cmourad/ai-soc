import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "sensor-control-helper.py"
SPEC = importlib.util.spec_from_file_location("sensor_control_helper", MODULE_PATH)
HELPER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(HELPER)


class Result:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class SensorControlHelperTest(unittest.TestCase):
    def test_pihole_status_normalizes_kubernetes_deployment(self):
        deployment = {
            "spec": {"replicas": 1},
            "status": {"availableReplicas": 1, "updatedReplicas": 1},
        }
        with patch.object(HELPER.subprocess, "run", return_value=Result(json.dumps(deployment))):
            response = HELPER.execute({"action": "status", "service": "pihole"})
        self.assertTrue(response["ok"])
        self.assertEqual(
            response["pihole"],
            {
                "installed": True,
                "running": True,
                "state": "running",
                "health": "healthy",
                "status": "1/1 replicas available",
            },
        )

    def test_status_rejects_every_service_except_pihole(self):
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            HELPER.execute({"action": "status", "service": "suricata"})

    def test_pihole_status_reports_rollout_as_starting(self):
        deployment = {"spec": {"replicas": 1}, "status": {"updatedReplicas": 1}}
        with patch.object(HELPER.subprocess, "run", return_value=Result(json.dumps(deployment))):
            response = HELPER.execute({"action": "status", "service": "pihole"})
        self.assertTrue(response["pihole"]["running"])
        self.assertEqual(response["pihole"]["state"], "starting")
        self.assertEqual(response["pihole"]["health"], "starting")

    def test_restart_allows_pihole_and_rejects_unknown_services(self):
        with patch.object(HELPER.subprocess, "run", return_value=Result()) as run:
            response = HELPER.execute({"action": "restart", "services": ["pihole"]})
        self.assertTrue(response["ok"])
        self.assertIn("delete", run.call_args.args[0])
        self.assertIn("app.kubernetes.io/name=aisoc-pihole", run.call_args.args[0])

        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            HELPER.execute({"action": "restart", "services": ["docker"]})

    def test_resolver_status_parses_script_json(self):
        payload = {"interface": "wlp7s0", "dns": ["192.0.2.9"], "routed": True}
        with patch.object(HELPER.subprocess, "run", return_value=Result(json.dumps(payload))):
            response = HELPER.execute({"action": "resolver", "mode": "status"})
        self.assertTrue(response["ok"])
        self.assertEqual(response["resolver"], payload)

    def test_resolver_rejects_revert_and_extra_keys(self):
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            HELPER.execute({"action": "resolver", "mode": "revert"})
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            HELPER.execute({"action": "resolver", "mode": "apply", "service": "pihole"})

    def test_resolver_apply_surfaces_failure_output(self):
        with patch.object(
            HELPER.subprocess, "run", return_value=Result(stderr="no address", returncode=1)
        ):
            response = HELPER.execute({"action": "resolver", "mode": "apply"})
        self.assertFalse(response["ok"])
        self.assertIn("no address", response["error"])


if __name__ == "__main__":
    unittest.main()

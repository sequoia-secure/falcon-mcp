"""
Tests for the opt-in RTR file collection module.
"""

from falcon_mcp import registry
from falcon_mcp.modules.rtr_collect import COLLECT_ANNOTATIONS, RTRCollectModule
from tests.modules.utils.test_modules import TestModules

AID = "0123456789abcdef0123456789abcdef"
PATH = "/Users/jdoe/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite"
WHY = "CASE-123 approved by CISO"


def ok(resources):
    return {"status_code": 200, "body": {"resources": resources}}


class TestRTRCollectModule(TestModules):
    def setUp(self):
        self.setup_module(RTRCollectModule)

    def collect(self, **overrides):
        args = {
            "device_id": AID,
            "file_path": PATH,
            "justification": WHY,
            "queue_offline": False,
            "timeout_seconds": 10,
            "poll_interval_seconds": 0,
        }
        args.update(overrides)
        return self.module.collect_file(**args)

    def test_register_tools(self):
        self.assert_tools_registered(["falcon_rtr_collect_file"])

    def test_tool_annotations(self):
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations("falcon_rtr_collect_file", COLLECT_ANNOTATIONS)

    def test_module_is_opt_in(self):
        self.assertIn("rtrcollect", registry.get_module_names())
        self.assertNotIn("rtrcollect", registry.get_default_module_names())

    def test_collects_and_returns_metadata_only(self):
        self.mock_client.command.side_effect = [
            ok([{"session_id": "sess-1"}]),
            ok([{"cloud_request_id": "req-1", "session_id": "sess-1"}]),
            ok([{"complete": False, "sequence_id": 0}]),
            ok([{"complete": True, "stdout": "", "stderr": ""}]),
            ok([]),
            ok(
                [
                    {
                        "cloud_request_id": "req-1",
                        "name": PATH,
                        "sha256": "ab" * 32,
                        "size": 1234,
                        "created_at": "2026-11-11T00:00:00Z",
                    }
                ]
            ),
        ]

        result = self.collect()

        self.mock_client.command.assert_any_call(
            "RTR_InitSession",
            body={"device_id": AID, "origin": "falcon-mcp-collect", "queue_offline": False},
        )
        self.mock_client.command.assert_any_call(
            "RTR_ExecuteActiveResponderCommand",
            body={
                "session_id": "sess-1",
                "device_id": AID,
                "base_command": "get",
                "command_string": f'get "{PATH}"',
                "persist": False,
            },
        )
        self.mock_client.command.assert_any_call(
            "RTR_CheckActiveResponderCommandStatus",
            parameters={"cloud_request_id": "req-1", "sequence_id": 0},
        )
        self.mock_client.command.assert_any_call(
            "RTR_ListFilesV2", parameters={"session_id": "sess-1"}
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["session_id"], "sess-1")
        self.assertEqual(result["file"]["sha256"], "ab" * 32)
        self.assertEqual(result["file"]["size"], 1234)
        self.assertNotIn("error", result)
        # No operation that returns file contents is ever called.
        ops = [c.args[0] for c in self.mock_client.command.call_args_list]
        self.assertNotIn("RTR_GetExtractedFileContents", ops)

    def test_get_error_on_host_is_reported(self):
        self.mock_client.command.side_effect = [
            ok([{"session_id": "sess-1"}]),
            ok([{"cloud_request_id": "req-1"}]),
            ok([{"complete": True, "stderr": "File not found"}]),
        ]
        result = self.collect()
        self.assertEqual(result["phase"], "get")
        self.assertIn("File not found", result["error"])
        self.assertEqual(self.mock_client.command.call_count, 3)

    def test_validation_rejects_before_any_api_call(self):
        cases = [
            {"device_id": "not-an-aid"},
            {"file_path": "relative/path.db"},
            {"file_path": "~/Library/x.db"},
            {"file_path": '/tmp/a" ; rm -rf /'},
            {"file_path": "/tmp/*.db"},
            {"justification": "  "},
            {"justification": "short"},
        ]
        for override in cases:
            with self.subTest(override=override):
                result = self.collect(**override)
                self.assertEqual(result["phase"], "validate")
        self.mock_client.command.assert_not_called()

    def test_windows_paths_accepted(self):
        self.mock_client.command.side_effect = [
            ok([{"session_id": "sess-1"}]),
            ok([{"cloud_request_id": "req-1"}]),
            ok([{"complete": True}]),
            ok([{"cloud_request_id": "req-1", "name": "x", "sha256": "s", "size": 1}]),
        ]
        result = self.collect(file_path=r"C:\Users\jdoe\AppData\Roaming\x.db")
        self.assertTrue(result["complete"])

    def test_init_failure_stops(self):
        self.mock_client.command.side_effect = [
            {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}},
        ]
        result = self.collect()
        self.assertEqual(result["phase"], "init_session")
        self.assertEqual(self.mock_client.command.call_count, 1)

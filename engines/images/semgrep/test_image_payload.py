import io
import tarfile
import unittest

from verify_image_payload import payload


class ImagePayloadTests(unittest.TestCase):
    def receipt(self, body=b"verified runtime", mode=0o555, hostname=b"runner-a", mtime=1, duplicate=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, content, permissions in (("opt/semgrep/bin/semgrep", body, mode), ("etc/hostname", hostname, 0o644)):
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(content), permissions, mtime
                archive.addfile(member, io.BytesIO(content))
                if duplicate:
                    archive.addfile(member, io.BytesIO(content))
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            return payload(archive)

    def test_runtime_bytes_and_execute_permissions_are_bound(self):
        expected = self.receipt()["rootfs_payload_sha256"]
        self.assertNotEqual(self.receipt(body=b"different runtime")["rootfs_payload_sha256"], expected)
        self.assertNotEqual(self.receipt(mode=0o777)["rootfs_payload_sha256"], expected)

    def test_runner_hostname_and_tar_timestamps_do_not_change_image_payload(self):
        self.assertEqual(self.receipt()["rootfs_payload_sha256"], self.receipt(hostname=b"runner-b", mtime=2)["rootfs_payload_sha256"])

    def test_duplicate_archive_members_are_refused(self):
        with self.assertRaisesRegex(ValueError, "repeated"):
            self.receipt(duplicate=True)


if __name__ == "__main__":
    unittest.main()

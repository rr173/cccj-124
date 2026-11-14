"""Bearer token 鉴权协商：401 challenge -> token 端点 -> 重试。"""

from fixtures import RegistryFixture
from oci_catalog import AuthError, RegistryClient


class TestAuth(RegistryFixture):
    auth_enabled = True

    def test_anonymous_request_is_challenged(self):
        client = RegistryClient(self.base_url)  # 无凭据
        with self.assertRaises(AuthError):
            client.list_repositories_page()

    def test_bad_credentials_rejected(self):
        client = RegistryClient(self.base_url, username="user",
                                password="wrong")
        with self.assertRaises(AuthError):
            client.ping()

    def test_full_flow_with_credentials(self):
        client = self.new_client()
        client.ping()  # 完成 catalog scope 的 token 协商
        # 不同 scope 会分别换取 token
        self.assertIn("registry:catalog:*", client._tokens)

        page = client.list_repositories_page(page_size=2)
        self.assertTrue(page.items)

        # 完整采集走通：manifest 使用 repository pull scope
        report = self.new_collector(client=client).run()
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.repositories_completed, 4)
        self.assertIn("repository:team-a/app:pull", client._tokens)

    def test_token_scope_is_enforced(self):
        client = self.new_client()
        # 手工塞入只有 catalog scope 的 token 去访问 manifest -> 403
        client._tokens["repository:team-a/app:pull"] = \
            self.registry.issue_token("registry:catalog:*")
        with self.assertRaises(AuthError):
            client.get_manifest("team-a/app", "latest")

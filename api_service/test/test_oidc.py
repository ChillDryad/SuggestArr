"""Unit tests for native OpenID Connect identity policy."""
import os
import unittest


class TestOIDCIdentityPolicy(unittest.TestCase):
    def setUp(self):
        self._saved = {key: os.environ.get(key) for key in (
            "OIDC_ALLOWED_GROUPS", "OIDC_ADMIN_GROUPS", "OIDC_USERNAME_CLAIM",
            "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_PUBLIC_URL",
        )}
        os.environ["OIDC_ALLOWED_GROUPS"] = "household"
        os.environ["OIDC_ADMIN_GROUPS"] = "admin"
        os.environ["OIDC_USERNAME_CLAIM"] = "preferred_username"
        os.environ["OIDC_ISSUER"] = "https://auth.example.test"
        os.environ["OIDC_CLIENT_ID"] = "suggestarr-test"
        os.environ["OIDC_CLIENT_SECRET"] = "test-client-secret"
        os.environ["OIDC_PUBLIC_URL"] = "https://suggestarr.example.test"

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_groups_claim_grants_admin_identity(self):
        from api_service.auth.oidc_service import OIDCService

        identity = OIDCService.identity_from_claims({
            "sub": "pocket-id-subject-123",
            "preferred_username": "dryad",
            "groups": ["household", "admin"],
        })

        self.assertEqual(identity.subject, "pocket-id-subject-123")
        self.assertEqual(identity.username, "dryad")
        self.assertEqual(identity.role, "admin")

    def test_missing_allowed_group_is_denied(self):
        from api_service.auth.oidc_service import OIDCAccessDenied, OIDCService

        with self.assertRaises(OIDCAccessDenied):
            OIDCService.identity_from_claims({
                "sub": "pocket-id-subject-456",
                "preferred_username": "outsider",
                "groups": ["guests"],
            })


if __name__ == "__main__":
    unittest.main()

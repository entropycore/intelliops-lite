
import unittest

from src.extraction import (
    masquer_secrets,
    normaliser_docker,
    normaliser_trivy,
)


LIGNE_DOCKER = (
    "2026-10-05 10:02:11 ERROR backend "
    "OOMKilled restarts=14 node=db-02"
)

RAPPORT_TRIVY = {
    "Target": "backend",
    "VulnerabilityID": "CVE-2026-1234",
    "PkgName": "lib",
    "InstalledVersion": "1.2.3",
    "Severity": "CRITICAL",
    "Timestamp": "2026-10-05T10:07:00Z",
}


class TestExtraction(unittest.TestCase):

    def test_masquer_secrets(self):
        texte = "login ok password=abc123 user=bob"

        resultat = masquer_secrets(texte)

        self.assertEqual(
            resultat,
            "login ok password=[SECRET] user=bob",
        )

    def test_masquer_secrets_sans_distinguer_la_casse(self):
        texte = "PASSWORD=abc TOKEN:xyz Api_Key=123"

        resultat = masquer_secrets(texte)

        self.assertEqual(
            resultat,
            "PASSWORD=[SECRET] TOKEN:[SECRET] Api_Key=[SECRET]",
        )

    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE_DOCKER, 125)

        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.source, "DOCKER")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.environment, "production")
        self.assertEqual(evt.event_type, "CONTAINER_RESTART")
        self.assertEqual(evt.severity, "HIGH")
        self.assertIn("OOMKilled", evt.message)

    def test_redemarrage_conteneur(self):
        evt = normaliser_docker(LIGNE_DOCKER, 1)

        self.assertEqual(evt.event_type, "CONTAINER_RESTART")
        self.assertIn("restarts=14", evt.message)

    def test_log_docker_sans_redemarrage(self):
        ligne = (
            "2026-10-05 10:09:00 INFO api "
            "health check ok"
        )

        evt = normaliser_docker(ligne, 2)

        self.assertEqual(evt.event_type, "LOG")
        self.assertEqual(evt.severity, "LOW")

    def test_secret_masque_dans_log_docker(self):
        ligne = (
            "2026-10-05 10:05:40 WARN frontend "
            "slow response password=abc123 time=2300ms"
        )

        evt = normaliser_docker(ligne, 3)

        self.assertIn("password=[SECRET]", evt.message)
        self.assertNotIn("abc123", evt.message)

    def test_normaliser_trivy(self):
        evt = normaliser_trivy(RAPPORT_TRIVY, 7)

        self.assertEqual(evt.id, "EVT-00007")
        self.assertEqual(evt.timestamp, "2026-10-05T10:07:00Z")
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.environment, "production")
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertEqual(
            evt.message,
            "Vulnérabilité CVE-2026-1234 détectée dans lib 1.2.3.",
        )

    def test_severite_trivy_inconnue(self):
        rapport = RAPPORT_TRIVY.copy()
        rapport["Severity"] = "INCONNUE"

        evt = normaliser_trivy(rapport, 8)

        self.assertEqual(evt.severity, "LOW")

    def test_donnees_trivy_manquantes(self):
        rapport = RAPPORT_TRIVY.copy()
        del rapport["PkgName"]

        with self.assertRaises(ValueError):
            normaliser_trivy(rapport, 9)

    def test_ligne_docker_trop_courte(self):
        with self.assertRaises(ValueError):
            normaliser_docker("2026-10-05 10:02:11 ERROR", 10)

    def test_date_docker_invalide(self):
        ligne = "date-invalide 10:02:11 ERROR backend message"

        with self.assertRaises(ValueError):
            normaliser_docker(ligne, 11)

    def test_timestamp_trivy_invalide(self):
        rapport = RAPPORT_TRIVY.copy()
        rapport["Timestamp"] = "date-invalide"

        with self.assertRaises(ValueError):
            normaliser_trivy(rapport, 12)


if __name__ == "__main__":
    unittest.main()

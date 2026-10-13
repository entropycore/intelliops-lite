import unittest
from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement

def evt(event_type="LOG", severity="LOW", message="ok", component="backend", source="DOCKER"):
    return Evenement(
        id="EVT-00001", 
        timestamp="2026-10-05T10:00:00Z", 
        source=source, 
        component=component,
        environment="production", 
        event_type=event_type, 
        severity=severity, 
        message=message
    )

class TestAnalyse(unittest.TestCase):
    def test_est_doublon(self):
        vus = set()
        e1 = evt(message="a")
        self.assertFalse(est_doublon(e1, vus))
        self.assertTrue(est_doublon(e1, vus))

    def test_rechercher_runbook_trouve(self):
        e = evt(message="Une erreur oomkilled est survenue")
        self.assertEqual(
            rechercher_runbook(e, RUNBOOKS), 
            "Limite mémoire : augmenter la limite du conteneur ou corriger la fuite mémoire."
        )
        
    def test_rechercher_runbook_inconnu(self):
        e = evt(message="Erreur réseau classique")
        self.assertIsNone(rechercher_runbook(e, RUNBOOKS))

    def test_classer_redemarrages_critiques(self):
        e = evt(event_type="CONTAINER_RESTART", severity="HIGH", message="OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")
        
    def test_classer_redemarrages_moyens(self):
        e = evt(event_type="CONTAINER_RESTART", severity="HIGH", message="OOMKilled restarts=5")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_vuln_critique_devient_high(self):
        e = evt(event_type="VULNERABILITY", severity="CRITICAL", message="CVE detectee")
        self.assertEqual(classer(e), "HIGH")
        
    def test_classer_defaut(self):
        e = evt(event_type="LOG", severity="LOW", message="tout va bien")
        self.assertEqual(classer(e), "LOW")

    # --- NOUVEAUX TESTS AJOUTÉS ---
    def test_analyser_evenement_non_sensible(self):
        e = evt(event_type="LOG", severity="LOW", message="tout va bien")
        analyse = analyser(e, RUNBOOKS)
        self.assertFalse(analyse.sensible)
        self.assertEqual(
            analyse.cause_probable,
            "Cause inconnue : analyse manuelle requise"
        )

    def test_classer_vulnerabilite_critical_en_minuscules(self):
        e = evt(event_type="VULNERABILITY", severity="critical")
        self.assertEqual(classer(e), "HIGH")
    # ------------------------------

    def test_analyser(self):
        e = evt(event_type="CONTAINER_RESTART", severity="HIGH", message="OOMKilled restarts=14", component="backend")
        analyse = analyser(e, RUNBOOKS)
        
        self.assertEqual(analyse.event_id, "EVT-00001")
        self.assertEqual(analyse.criticite, "CRITICAL")
        self.assertEqual(analyse.cause_probable, "Limite mémoire : augmenter la limite du conteneur ou corriger la fuite mémoire.")
        self.assertEqual(analyse.action_recommandee, "Redémarrer backend")
        self.assertTrue(analyse.sensible)
        self.assertEqual(analyse.sources, ["DOCKER"])
        self.assertEqual(e.status, "ANALYSED")

if __name__ == "__main__":
    unittest.main()
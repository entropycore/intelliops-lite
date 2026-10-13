import unittest
from src.contrat import Analyse, Evenement
from src.notification import choisir_canal, demander_validation, notifier, rediger

def exemple(sensible=True, criticite="CRITICAL"):
    e = Evenement(
        id="EVT-00125", 
        timestamp="2026-10-05T10:02:11Z", 
        source="DOCKER", 
        component="backend",
        environment="production", 
        event_type="CONTAINER_RESTART", 
        severity="HIGH",
        message="OOMKilled restarts=14"
    )
    a = Analyse(
        event_id="EVT-00125", 
        criticite=criticite, 
        cause_probable="Limite mémoire", 
        action_recommandee="Redémarrer backend",
        sensible=sensible, 
        sources=["DOCKER", "TRIVY"]
    )
    return e, a

class TestNotification(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")
        
        with self.assertRaises(ValueError):
            choisir_canal("UNKNOWN")

    def test_rediger(self):
        e, a = exemple()
        attendu = (
            "[CRITICAL] Service : backend\n"
            "Incident : OOMKilled restarts=14\n"
            "Cause probable : Limite mémoire\n"
            "Action : Redémarrer backend\n"
            "Sources : DOCKER, TRIVY"
        )
        self.assertEqual(rediger(e, a), attendu)

    def test_notifier(self):
        e, a = exemple()
        journal = []
        notif = notifier(e, a, journal)
        
        self.assertEqual(notif.canal, "TEAMS")
        self.assertEqual(notif.destinataire, "equipe-ops")
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0], notif)
        self.assertEqual(e.status, "NOTIFIED")

    def test_validation_sensible_acceptee(self):
        e, a = exemple(sensible=True)
        self.assertTrue(demander_validation(a, "o"))
        self.assertTrue(demander_validation(a, " OUI "))
        self.assertTrue(demander_validation(a, "yes"))
        self.assertTrue(demander_validation(a, "Y"))

    def test_validation_sensible_refusee(self):
        e, a = exemple(sensible=True)
        self.assertFalse(demander_validation(a, "n"))
        self.assertFalse(demander_validation(a, "non"))
        self.assertFalse(demander_validation(a, ""))

    def test_validation_non_sensible(self):
        e, a = exemple(sensible=False)
        self.assertTrue(demander_validation(a, "n"))  # Renvoie True quoi qu'il arrive

if __name__ == "__main__":
    unittest.main()
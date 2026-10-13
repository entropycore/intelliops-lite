from src.contrat import Analyse, Evenement, Notification

def choisir_canal(criticite: str) -> str:
    if criticite in ["CRITICAL", "HIGH"]:
        return "TEAMS"
    elif criticite == "MEDIUM":
        return "EMAIL"
    elif criticite == "LOW":
        return "DASHBOARD"
    else:
        raise ValueError(f"Criticité inconnue : {criticite}")

def rediger(evt: Evenement, analyse: Analyse) -> str:
    # Joint les sources avec une virgule et un espace
    sources_formatees = ", ".join(analyse.sources)
    
    # Prépare les 5 lignes exactes demandées par le contrat
    lignes = [
        f"[{analyse.criticite}] Service : {evt.component}",
        f"Incident : {evt.message}",
        f"Cause probable : {analyse.cause_probable}",
        f"Action : {analyse.action_recommandee}",
        f"Sources : {sources_formatees}"
    ]
    
    # Sépare les lignes par des retours à la ligne (\n)
    return "\n".join(lignes)

def notifier(evt: Evenement, analyse: Analyse, journal: list) -> Notification:
    canal = choisir_canal(analyse.criticite)
    message = rediger(evt, analyse)
    
    # Crée la notification avec equipe-ops comme destinataire par défaut
    notification = Notification(
        event_id=evt.id,
        canal=canal,
        destinataire="equipe-ops",
        message=message
    )
    
    # Historise et met à jour le statut
    journal.append(notification)
    evt.status = "NOTIFIED"
    
    return notification

def demander_validation(analyse: Analyse, reponse: str) -> bool:
    if not analyse.sensible:
        return True
        
    # Supprime les espaces autour et met en minuscules
    rep = reponse.strip().lower()
    return rep in ["o", "oui", "y", "yes"]
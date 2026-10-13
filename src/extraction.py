
import re
from datetime import datetime

from src.contrat import Evenement, SEVERITES


def masquer_secrets(texte: str) -> str:
    """
    Masque les valeurs de password, passwd, token, secret et api_key.
    La recherche ne distingue pas les majuscules des minuscules.
    """
    pattern = r"\b(password|passwd|token|secret|api_key)(\s*[=:]\s*)([^\s,;]+)"

    return re.sub(
        pattern,
        lambda match: match.group(1) + match.group(2) + "[SECRET]",
        texte,
        flags=re.IGNORECASE,
    )


def normaliser_docker(
    ligne: str,
    numero: int,
    environment: str = "production",
) -> Evenement:
    """
    Convertit une ligne de log Docker en objet Evenement.
    Format attendu :
    AAAA-MM-JJ HH:MM:SS NIVEAU composant message...
    """
    champs = ligne.split()

    if len(champs) < 5:
        raise ValueError("Ligne Docker invalide : au moins 5 champs sont requis.")

    date = champs[0]
    heure = champs[1]
    niveau = champs[2].upper()
    component = champs[3]
    message = " ".join(champs[4:])

    # Vérifier le format de la date et de l'heure.
    try:
        datetime.strptime(f"{date} {heure}", "%Y-%m-%d %H:%M:%S")
    except ValueError as erreur:
        raise ValueError("Date ou heure Docker invalide.") from erreur

    timestamp = f"{date}T{heure}Z"

    # Convertir le niveau Docker en gravité commune.
    correspondance = {
        "ERROR": "HIGH",
        "WARN": "MEDIUM",
        "INFO": "LOW",
    }
    severity = correspondance.get(niveau, "LOW")

    # Détecter les redémarrages de conteneurs.
    event_type = (
        "CONTAINER_RESTART"
        if re.search(r"\brestarts\s*=", message, re.IGNORECASE)
        else "LOG"
    )

    # Masquer les secrets avant de conserver le message.
    message = masquer_secrets(message)

    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=timestamp,
        source="DOCKER",
        component=component,
        environment=environment,
        event_type=event_type,
        severity=severity,
        message=message,
    )


def normaliser_trivy(
    rapport: dict,
    numero: int,
    environment: str = "production",
) -> Evenement:
    """
    Convertit un rapport Trivy en objet Evenement.
    """
    cles_requises = [
        "Target",
        "VulnerabilityID",
        "PkgName",
        "InstalledVersion",
        "Severity",
        "Timestamp",
    ]

    if not isinstance(rapport, dict):
        raise ValueError("Le rapport Trivy doit être un dictionnaire.")

    cles_manquantes = [
        cle for cle in cles_requises if cle not in rapport
    ]

    if cles_manquantes:
        raise ValueError(
            "Clé(s) manquante(s) dans le rapport Trivy : "
            + ", ".join(cles_manquantes)
        )

    try:
        date = datetime.fromisoformat(
            rapport["Timestamp"].replace("Z", "+00:00")
        )
    except (ValueError, AttributeError, TypeError) as erreur:
        raise ValueError("Timestamp Trivy invalide.") from erreur

    timestamp = date.strftime("%Y-%m-%dT%H:%M:%SZ")

    severity_brute = str(rapport["Severity"]).upper()
    severity = (
        severity_brute
        if severity_brute in SEVERITES
        else "LOW"
    )

    component = str(rapport["Target"])
    vulnerability_id = str(rapport["VulnerabilityID"])
    package = str(rapport["PkgName"])
    version = str(rapport["InstalledVersion"])

    message = (
        f"Vulnérabilité {vulnerability_id} détectée "
        f"dans {package} {version}."
    )

    message = masquer_secrets(message)

    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=timestamp,
        source="TRIVY",
        component=component,
        environment=environment,
        event_type="VULNERABILITY",
        severity=severity,
        message=message,
    )

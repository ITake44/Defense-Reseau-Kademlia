import subprocess
import re
from statistics import mean

# =========================
# CONFIGURATION
# =========================

N_SIMULATIONS = 300

WORKING_DIR = r"C:\TMP\TIPE_2\peersim-1.0.5(1)\peersim-1.0.5-main"

JAVA_COMMAND = [
    "java",
    "-classpath",
    "classes;kademlia/classes;jep-2.3.0.jar;djep-1.0.0.jar;peersim-1.0.5.jar",
    "peersim.Simulator",
    "kademlia/example.cfg"
]

# =========================
# REGEX
# =========================

SYBIL_REGEX = re.compile(
    r"Target searches:\s+(\d+).*?Censored:\s+\d+\s+\(([0-9]+,[0-9]+)%\)"
)

TIME_REGEX = re.compile(
    r"\[time=(\d+)\]"
)

DETECTION_REGEX = re.compile(
    r"Periodic detections:\s+(\d+)\s+positive\s+\|\s+(\d+)\s+negative"
)

MITIGATION_APPLY_REGEX = re.compile(
    r"Extended closestKNodes to (\d+) nodes"
)

# =========================
# FONCTION DE SIMULATION
# =========================

def lancer_simulation(simulation_id):

    print(f"\n===== Simulation {simulation_id} =====")

    process = subprocess.run(
        JAVA_COMMAND,
        cwd=WORKING_DIR,
        capture_output=True,
        text=True
    )

    output = process.stdout + process.stderr

    lignes = output.splitlines()

    dernier_time = None

    premiere_defense_time = None

    censure_finale = None

    detections_positives = 0
    detections_totales = 0

    taille_finale_closest = None

    for ligne in lignes:

        # =========================
        # Temps courant
        # =========================

        time_match = TIME_REGEX.search(ligne)

        if time_match:
            dernier_time = int(
                time_match.group(1)
            )

        # =========================
        # Statistiques Sybil
        # =========================

        if "[SYBIL STATS]" in ligne:

            match = SYBIL_REGEX.search(ligne)

            if match:

                target_searches = int(
                    match.group(1)
                )

                censure = float(
                    match.group(2).replace(",", ".")
                )

                censure_finale = censure

                # Premier moment où la
                # défense agit réellement

                if (
                    target_searches > 0
                    and censure < 100.0
                    and premiere_defense_time is None
                ):
                    premiere_defense_time = dernier_time

        # =========================
        # Statistiques détection
        # =========================

        if "[DETECTION STATS]" in ligne:

            detection_match = DETECTION_REGEX.search(
                ligne
            )

            if detection_match:

                positives = int(
                    detection_match.group(1)
                )

                negatives = int(
                    detection_match.group(2)
                )

                detections_positives = positives

                detections_totales = (
                    positives + negatives
                )

        # =========================
        # Taille finale closestKNodes
        # =========================

        mitigation_match = (
            MITIGATION_APPLY_REGEX.search(ligne)
        )

        if mitigation_match:

            taille_finale_closest = int(
                mitigation_match.group(1)
            )

    # =========================
    # AFFICHAGE SIMULATION
    # =========================

    print("\n-----------------------------")
    print(f"RÉSULTATS SIMULATION {simulation_id}")
    print("-----------------------------")

    print(
        f"Censure finale : "
        f"{censure_finale:.2f}%"
    )

    if censure_finale == 100.0:
        print(
            "Statut final   : "
            "Attaque réussie"
        )
    else:
        print(
            "Statut final   : "
            "Défense réussie"
        )

    # Temps réaction défense

    if premiere_defense_time is not None:

        print(
            f"Premier instant où "
            f"la défense agit : "
            f"{premiere_defense_time} ms "
            f"({premiere_defense_time / 60000:.2f} min)"
        )

    else:

        print(
            "La défense n'a jamais "
            "réduit la censure sous 100%"
        )

    # Détections

    print(
        f"Détections positives : "
        f"{detections_positives}"
    )

    print(
        f"Détections totales   : "
        f"{detections_totales}"
    )

    # closestKNodes

    if taille_finale_closest is not None:

        print(
            f"Taille finale "
            f"closestKNodes : "
            f"{taille_finale_closest}"
        )

    print("-----------------------------")

    # =========================
    # RETURN
    # =========================

    return {
        "censure_finale": censure_finale,
        "premiere_defense_time":
            premiere_defense_time,
        "detections_positives":
            detections_positives,
        "detections_totales":
            detections_totales,
        "taille_finale_closest":
            taille_finale_closest
    }

# =========================
# BOUCLE PRINCIPALE
# =========================

resultats = []

for i in range(1, N_SIMULATIONS + 1):

    resultat = lancer_simulation(i)

    if resultat is not None:
        resultats.append(resultat)

# =========================
# STATISTIQUES GLOBALES
# =========================

if resultats:

    print("\n===================================")
    print("RÉSUMÉ GLOBAL")
    print("===================================")

    # =========================
    # Taux réussite défense
    # =========================

    defenses_reussies = sum(
        r["censure_finale"] != 100.0
        for r in resultats
    )

    taux_reussite = (
        100
        * defenses_reussies
        / len(resultats)
    )

    print(
        f"Taux de réussite "
        f"de la défense : "
        f"{taux_reussite:.2f}%"
    )

    # =========================
    # Censure moyenne
    # =========================

    print(
        f"Censure finale moyenne : "
        f"{mean(r['censure_finale'] for r in resultats):.2f}%"
    )

    # =========================
    # Temps moyen réaction
    # =========================

    temps_valides = [

        r["premiere_defense_time"]

        for r in resultats

        if r["premiere_defense_time"]
        is not None
    ]

    if temps_valides:

        temps_moyen = mean(
            temps_valides
        )

        print(
            f"Temps moyen de réaction "
            f"de la défense : "
            f"{temps_moyen:.0f} ms "
            f"({temps_moyen / 60000:.2f} min)"
        )

    # =========================
    # Détections positives
    # =========================

    print(
        f"Détections positives moyennes : "
        f"{mean(r['detections_positives'] for r in resultats):.2f}"
    )

    # =========================
    # Détections totales
    # =========================

    print(
        f"Détections totales moyennes : "
        f"{mean(r['detections_totales'] for r in resultats):.2f}"
    )

    # =========================
    # Taille moyenne closestKNodes
    # =========================

    tailles_valides = [

        r["taille_finale_closest"]

        for r in resultats

        if r["taille_finale_closest"]
        is not None
    ]

    if tailles_valides:

        print(
            f"Taille moyenne "
            f"de closestKNodes : "
            f"{mean(tailles_valides):.2f}"
        )

    print("===================================")
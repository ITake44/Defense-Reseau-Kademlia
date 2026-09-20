package peersim.kademlia;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Control;
import peersim.core.Network;
import peersim.core.Node;
import peersim.util.IncrementalStats;

/**
 * This class implements a simple observer of search time and hop average in finding a node in the network.
 * It also tracks Sybil attack statistics to measure censorship effectiveness.
 * 
 */
public class KademliaObserver implements Control {

    /**
     * keep statistics of the number of hops of every message delivered.
     */
    public static IncrementalStats hopStore = new IncrementalStats();

    /**
     * keep statistics of the time every message delivered.
     */
    public static IncrementalStats timeStore = new IncrementalStats();

    /**
     * keep statistic of number of message delivered
     */
    public static IncrementalStats msg_deliv = new IncrementalStats();

    /**
     * keep statistic of number of find operation
     */
    public static IncrementalStats find_op = new IncrementalStats();

    /**
     * ===== STATISTIQUES SYBIL =====
     * Nombre total de recherches ciblant la valeur Sybil
     */
    public static int targetSearchCount = 0;

    /**
     * Nombre de recherches ciblant la valeur Sybil qui ont été CENSURÉES
     * (tous les K plus proches voisins sont des Sybils)
     */
    public static int censoredSearchCount = 0;

    /**
     * Nombre de recherches ciblant la valeur Sybil qui ont ÉCHOUÉ à trouver
     * les données (pas de réponse des Sybils)
     */
    public static int failedSearchCount = 0;

    /**
     * Nombre de recherches ciblant la valeur Sybil qui ont réussi
     * (au moins un nœud non-Sybil trouvé parmi les K plus proches)
     */
    public static int successfulSearchCount = 0;

    /**
     * Taux de censure (censoredSearchCount / targetSearchCount)
     */
    public static double censorshipRate = 0.0;
    
    /**
     * ===== STATISTIQUES DÉTECTION SYBIL =====
     * Nombre de détections positives (attaque détectée)
     */
    public static int detectionPositives = 0;
    
    /**
     * Nombre de détections négatives (pas d'attaque détectée)
     */
    public static int detectionNegatives = 0;
    
    /**
     * Liste pour stocker tous les résultats de détection pour analyse
     */
    public static java.util.ArrayList<Object> detectionResults = 
        new java.util.ArrayList<>();

    /**
     * Nombre total de nœuds Sybils dans le réseau
     */
    private int totalSybilNodes = 0;

    /**
     * Nombre de nœuds normaux dans le réseau
     */
    private int totalNormalNodes = 0;

    /**
     * Liste des K plus proches nœuds de la cible (calculée une fois)
     */
    public static java.util.HashSet<BigInteger> closestKNodes = new java.util.HashSet<>();

    // ===== ECHANTILLON DE RÉFÉRENCE POUR DÉTECTION SYBIL =====
    /**
     * Classe contenant les statistiques de référence (sans attaque Sybil)
     * Utilisée pour la détection d'anomalies 
     */
    public static class ReferenceBaseline {
        // Statistiques K-distance
        public double meanKDistance;        // moyenne K-distance 
        public double stdDevKDistance;      // écart-type K-distance
        public double medianKDistance;      // médiane K-distance
        public int totalSamples;            // Nombre d'échantillons utilisés
        
        // Statistiques bit-length 
        public int minBits;                 // longueur bit min observée
        public int maxBits;                 // longueur bit max observée
        public int[] bitLengthValues;       // valeurs distinctes de bitLength observées
        public int[] bitLengthFrequencies;  // fréquence de chaque bitLength
        
        // Flag
        public boolean isReady;             // Flag : référence calculée ?
        
        @Override
        public String toString() {
            int numDistinct = (bitLengthValues != null) ? bitLengthValues.length : 0;
            return String.format("[REFERENCE] Mean=2^%.2f | Median=2^%.2f | StdDev=%.3f | Bits:[%d,%d] | Samples=%d | Distinct=%d | Ready=%s",
                meanKDistance, medianKDistance, stdDevKDistance, minBits, maxBits, totalSamples, numDistinct, isReady);
        }
    }
    
    /**
     * Instance statique de la référence baseline (partagée entre tous les nœuds)
     */
    public static ReferenceBaseline referenceBaseline = null;

    /** Parameter of the protocol we want to observe */
    private static final String PAR_PROT = "protocol";

    /** Protocol id */
    private int pid;

    /** Prefix to be printed in output */
    private String prefix;

    /** Target node ID for distance calculation */
    public static BigInteger targetNodeId = new BigInteger("409281074974745890872116138270055241252539876");

    public KademliaObserver(String prefix) {
        this.prefix = prefix;
        pid = Configuration.getPid(prefix + "." + PAR_PROT);
    }

    /**
     * Compte le nombre de nœuds Sybils et normaux dans le réseau
     */
    private void countNodeTypes() {
        this.totalSybilNodes = 0;
        this.totalNormalNodes = 0;

        for (int i = 0; i < Network.size(); i++) {
            Node n = Network.get(i);
            if (n.isUp()) {
                KademliaProtocol proto = (KademliaProtocol) n.getProtocol(pid);
                if (proto.isSybil()) {
                    this.totalSybilNodes++;
                } else {
                    this.totalNormalNodes++;
                }
            }
        }
    }

    /**
     * Calcule le taux de censure actuel
     */
    private void updateCensorshipRate() {
        if (targetSearchCount > 0) {
            this.censorshipRate = (double) censoredSearchCount / targetSearchCount;
        } else {
            this.censorshipRate = 0.0;
        }
    }

    /**
     * Calcule les K plus proches nœuds de la cible (une seule fois)
     * et les stocke dans closestKNodes
     */
    private void calculateClosestKNodes() {
        if (!closestKNodes.isEmpty()) {
            return; // Déjà calculé
        }

        // Créer une liste de tous les nœuds avec leur distance à la cible
        java.util.List<java.util.AbstractMap.SimpleEntry<BigInteger, BigInteger>> nodeDistances = 
            new java.util.ArrayList<>();

        for (int i = 0; i < Network.size(); i++) {
            Node n = Network.get(i);
            if (n.isUp()) {
                KademliaProtocol proto = (KademliaProtocol) n.getProtocol(pid);
                BigInteger distance = Util.distance(proto.nodeId, targetNodeId);
                nodeDistances.add(new java.util.AbstractMap.SimpleEntry<>(proto.nodeId, distance));
            }
        }

        // Trier par distance
        nodeDistances.sort((a, b) -> a.getValue().compareTo(b.getValue()));

        // Prendre les K plus proches
        int k = KademliaCommonConfig.K;
        for (int i = 0; i < Math.min(k, nodeDistances.size()); i++) {
            closestKNodes.add(nodeDistances.get(i).getKey());
        }

        System.err.println("[OBSERVER] Calculated " + closestKNodes.size() + " closest nodes to target");
    }


    /**
     * Stocke les statistiques de simulation à chaque timestep pour export final
     * (Timestamp, NormalNodes, SybilNodes, AverageHops, AverageLatency, CensoredSearches, CensorshipRate)
     */
    private static java.util.List<SimulationSnapshot> simulationSnapshots = new java.util.ArrayList<>();
    
    /**
     * Classe interne pour stocker un snapshot des statistiques
     */
    private static class SimulationSnapshot {
        long timestamp;
        int normalNodes;
        int sybilNodes;
        double avgHops;
        double avgLatency;
        int censoredSearches;
        double censorshipRate;
        
        SimulationSnapshot(long timestamp, int normalNodes, int sybilNodes, 
                          double avgHops, double avgLatency, int censoredSearches, double censorshipRate) {
            this.timestamp = timestamp;
            this.normalNodes = normalNodes;
            this.sybilNodes = sybilNodes;
            this.avgHops = avgHops;
            this.avgLatency = avgLatency;
            this.censoredSearches = censoredSearches;
            this.censorshipRate = censorshipRate;
        }
    }

    /**
     * Exporte la distribution des nœuds autour de la cible
     * Crée un fichier CSV: NodeId,Distance,Type,Timestamp
     */
    private void exportNodesDistribution() {
        try {
            String filename = "nodes_distribution.csv";
            
            // Nettoyer l'ancien fichier au démarrage (première exportation)
            if (CommonState.getTime() == 3500000) {
                File f = new File(filename);
                if (f.exists()) {
                    f.delete();
                }
            }
            
            BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true));
            
            // Entête (une seule fois)
            File f = new File(filename);
            if (!f.exists() || f.length() == 0) {
                writer.write("Timestamp,NodeId,Distance,Type\n");
            }
            
            long currentTime = CommonState.getTime();
            
            // Exporter chaque nœud
            for (int i = 0; i < Network.size(); i++) {
                Node n = Network.get(i);
                if (n.isUp()) {
                    KademliaProtocol proto = (KademliaProtocol) n.getProtocol(pid);
                    BigInteger nodeId = proto.nodeId;
                    
                    // Calculer la distance XOR avec la cible
                    BigInteger distance = Util.distance(nodeId, targetNodeId);
                    
                    // Déterminer le type
                    String type = proto.isSybil() ? "Sybil" : "Normal";
                    
                    // Écrire: Time,NodeId,Distance,Type
                    writer.write(String.format("%d,%s,%s,%s\n", 
                        currentTime, nodeId, distance, type));
                }
            }
            
            writer.close();
            System.err.println("[EXPORT] Distribution exportée à " + filename);
            
        } catch (IOException e) {
            System.err.println("[ERROR] Impossible d'exporter la distribution: " + e.getMessage());
        }
    }


    public boolean execute() {
        // get the real network size
        int sz = Network.size();
        for (int i = 0; i < Network.size(); i++)
            if (!Network.get(i).isUp())
                sz--;

        // Calculer les K plus proches nœuds une seule fois
        calculateClosestKNodes();

        // Compter les types de nœuds
        countNodeTypes();
        updateCensorshipRate();
        

        // Enregistrer le snapshot de simulation pour export
        SimulationSnapshot snapshot = new SimulationSnapshot(
            CommonState.getTime(),
            this.totalNormalNodes,
            this.totalSybilNodes,
            hopStore.getAverage(),
            timeStore.getAverage(),
            censoredSearchCount,
            censorshipRate
        );
        simulationSnapshots.add(snapshot);

        // Affichage des statistiques normales
        String s = String.format(
            "[time=%d]:[N=%d current nodes UP] [D=%f msg deliv] [%f min h] [%f average h] [%f max h] [%d min l] [%d msec average l] [%d max l]",
            CommonState.getTime(), sz, msg_deliv.getSum(), hopStore.getMin(), hopStore.getAverage(),
            hopStore.getMax(), (int) timeStore.getMin(), (int) timeStore.getAverage(), (int) timeStore.getMax());

        // Affichage des statistiques Sybil
        String sybilStats = String.format(
            "[SYBIL STATS] Normal nodes: %d | Sybil nodes: %d | Target searches: %d | Censored: %d (%.2f%%) | Successful: %d | Failed: %d",
            this.totalNormalNodes, this.totalSybilNodes, targetSearchCount, censoredSearchCount,
            censorshipRate * 100, successfulSearchCount, failedSearchCount);

        System.err.println(s);
        System.err.println(sybilStats);
        
        // À la fin de la simulation, écrire les statistiques dans des fichiers
        if (CommonState.getTime() == 3500000) {
            // Log detection statistics SEULEMENT à la fin
            String detectionStats = String.format(
                "[DETECTION STATS] Periodic detections: %d positive | %d negative | Total in results list: %d",
                detectionPositives, detectionNegatives, detectionResults.size());
            System.err.println(detectionStats);

            exportNodesDistribution();
            exportSimulationStats();
            exportBaselineDistribution();
            exportDetectionResults();     
        }

        return false;
    }

    /**
     * Trouve les K plus proches voisins d'un nœud échantillon dans TOUT le réseau
     * (pas seulement ses voisins connus via la RoutingTable)
     * 
     * Complexité : O(N log N) où N = taille du réseau  
     * 
     * @param queryNodeId ID du nœud dont on cherche les K plus proches voisins
     * @param k nombre de voisins à trouver
     * @return Array des K plus proches IDs (triés par distance XOR)
     */
    private BigInteger[] findKNearestNeighborsGlobal(BigInteger queryNodeId, int k) {
        // Créer une liste (nodeId, distance XOR)
        java.util.List<java.util.AbstractMap.SimpleEntry<BigInteger, BigInteger>> nodesWithDistance = 
            new java.util.ArrayList<>();
        
        // Parcourir TOUS les nœuds du réseau
        for (int i = 0; i < Network.size(); i++) {
            Node node = Network.get(i);
            if (!node.isUp()) continue;
            
            KademliaProtocol proto = (KademliaProtocol) node.getProtocol(pid);
            BigInteger nodeId = proto.nodeId;
            
            // Calculer distance XOR
            BigInteger distance = Util.distance(queryNodeId, nodeId);
            nodesWithDistance.add(
                new java.util.AbstractMap.SimpleEntry<>(nodeId, distance)
            );
        }
        
        // Trier par distance XOR croissante
        nodesWithDistance.sort((a, b) -> a.getValue().compareTo(b.getValue()));
        
        // Extraire les K plus proches
        BigInteger[] kNearest = new BigInteger[Math.min(k, nodesWithDistance.size())];
        for (int i = 0; i < kNearest.length; i++) {
            kNearest[i] = nodesWithDistance.get(i).getKey();
        }
        
        return kNearest;
    }







    /**
     * Exporte les statistiques de simulation à chaque timestep
     * Fichier: simulation_stats.csv
     */
    public static void exportSimulationStats() {
        String filename = "simulation_stats.csv";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            // En-têtes
            writer.write("Timestamp,NormalNodes,SybilNodes,AverageHops,AverageLatency,CensoredSearches,CensorshipRate\n");
            
            // Données
            for (SimulationSnapshot snapshot : simulationSnapshots) {
                writer.write(String.format(java.util.Locale.US, "%d,%d,%d,%.6f,%.2f,%d,%.6f\n",
                    snapshot.timestamp,
                    snapshot.normalNodes,
                    snapshot.sybilNodes,
                    snapshot.avgHops,
                    snapshot.avgLatency,
                    snapshot.censoredSearches,
                    snapshot.censorshipRate));
            }
            
            System.out.println("[EXPORT] Simulation stats exportes vers: " + filename);
        } catch (IOException e) {
            System.err.println("[ERROR] Impossible d'exporter simulation stats: " + e.getMessage());
        }
    }

    /**
     * Exporte la distribution baseline (bitLength -> count)
     * Fichier: baseline_distribution.csv
     */
    public static void exportBaselineDistribution() {
        if (referenceBaseline == null || !referenceBaseline.isReady) {
            System.out.println("[EXPORT] Baseline not ready, skipping distribution export");
            return;
        }
        
        String filename = "baseline_distribution.csv";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            // En-têtes
            writer.write("bitLength,count\n");
            
            // Données - mapping des bitLengthValues vers bitLengthFrequencies
            if (referenceBaseline.bitLengthValues != null && referenceBaseline.bitLengthFrequencies != null) {
                for (int i = 0; i < referenceBaseline.bitLengthValues.length; i++) {
                    writer.write(String.format("%d,%d\n",
                        referenceBaseline.bitLengthValues[i],
                        referenceBaseline.bitLengthFrequencies[i]));
                }
            }
            
            System.out.println("[EXPORT] Baseline distribution exportee vers: " + filename);
        } catch (IOException e) {
            System.err.println("[ERROR] Impossible d'exporter baseline distribution: " + e.getMessage());
        }
    }

    /**
     * Exporte tous les résultats de détection au format CSV
     * pour analyse post-simulation.
     */
    public static void exportDetectionResults() {
        if (detectionResults.isEmpty()) {
            System.out.println("[DETECTION-EXPORT] Aucun résultat à exporter");
            return;
        }
        
        String filename = "detection_results.csv";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            // En-têtes - version pour Anomaly Detector
            writer.write("SampleIndex,AnomalyScore,Threshold,AttackDetected,SamplesAnalyzed,MeanBitLength,OutlierPercentage,Diagnostics\n");
            
            // Données - FORCER LOCALE ANGLAISE pour points décimaux au lieu de virgules
            int index = 0;
            for (Object resultObj : detectionResults) {
                if (resultObj instanceof SybilAnomalyDetector.DetectionResult) {
                    SybilAnomalyDetector.DetectionResult result = (SybilAnomalyDetector.DetectionResult) resultObj;
                    String line = String.format(java.util.Locale.US, "%d,%.6f,%.4f,%d,%d,%.2f,%.2f,\"%s\"\n",
                        index++,
                        result.anomalyScore,
                        result.threshold,
                        result.isAttackDetected ? 1 : 0,
                        result.samplesAnalyzed,
                        result.meanBitLength,
                        result.outlierPercentage,
                        result.diagnostics.replace("\"", ""));
                    writer.write(line);
                }
            }
            
            System.out.println("[DETECTION-EXPORT] Résultats exportés vers: " + filename);
            System.out.println("[DETECTION-SUMMARY] Détections positives: " + detectionPositives + " | Détections négatives: " + detectionNegatives);
            
            // Export baseline reference at end of detection results
            if (referenceBaseline != null && referenceBaseline.isReady) {
                System.out.println("[DETECTION-BASELINE] Mean K-distance: 2^" + String.format("%.2f", referenceBaseline.meanKDistance));
                System.out.println("[DETECTION-BASELINE] StdDev: " + String.format("%.3f", referenceBaseline.stdDevKDistance) + " bits");
                System.out.println("[DETECTION-BASELINE] Median: 2^" + String.format("%.0f", referenceBaseline.medianKDistance));
                System.out.println("[DETECTION-BASELINE] Samples: " + referenceBaseline.totalSamples);
            }
        } catch (IOException e) {
            System.err.println("[ERROR] Impossible d'exporter résultats: " + e.getMessage());
        }
    }
}

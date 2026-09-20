package peersim.kademlia;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Sybil Attack Detection using Outlier-based Anomaly Detection.
 * 
 * This detector identifies Sybil nodes by detecting anomalous K-distances:
 * - Sybils are assigned IDs close to a target (proximity_bits constraint)
 * - This makes their K-distances OUTLIERS compared to normal distribution
 * - We detect when too many K-distances are outside normal range
 * 
 * Method:
 * 1. Baseline: stores min/max and statistics of normal K-distances
 * 2. On test: measure K-distances and check for outliers
 * 3. If outlier percentage exceeds threshold → Sybil attack detected
 * 
 */
public class SybilAnomalyDetector {
    
    /**
     * Result of anomaly detection test
     */
    public static class DetectionResult {
        public boolean isAttackDetected;
        public double anomalyScore;          // 0-1: how anomalous is this sample?
        public int outlierCount;             // number of outlier values
        public int samplesAnalyzed;          // total samples analyzed
        public double outlierPercentage;     // outlier count / total
        public double meanBitLength;         // mean of observed bit lengths
        public double threshold;             // threshold used
        public String diagnostics;           // detailed message
        
        @Override
        public String toString() {
            return String.format(
                "[ANOMALY] Outliers=%d/%d (%.1f%%) | Mean=%.2f | Score=%.4f | Threshold=%.4f | Attack=%s",
                outlierCount, samplesAnalyzed, outlierPercentage,
                meanBitLength, anomalyScore, threshold, isAttackDetected);
        }
    }
    
    /**
     * Performs outlier-based anomaly detection on observed K-distances.
     * Analyzes the provided set of nodes to detect anomalous (Sybil-like) outliers.
     * 
     * @param closestSet HashMap of nodes found by the multiple research
     * @param destNode Target node being searched
     * @param referenceBaseline Reference baseline with baseline statistics
     * @param threshold Outlier percentage threshold (typically 0.50 = 50%)
     * @param closestKNodesSize Current size of the defensive node cache
     * @return DetectionResult with anomaly score and attack verdict
     */
    public static DetectionResult performAnomalyDetection(
            HashMap<BigInteger, Boolean> closestSet,
            BigInteger destNode,
            KademliaObserver.ReferenceBaseline referenceBaseline,
            double threshold,
            int closestKNodesSize) {
        
        DetectionResult result = new DetectionResult();
        result.threshold = threshold;
        
        // Validate baseline is ready
        if (referenceBaseline == null || !referenceBaseline.isReady) {
            result.diagnostics = "Baseline not ready";
            result.isAttackDetected = false;
            return result;
        }
        
        // Extract bit lengths of K distances from closest set
        List<Integer> observedBitLengths = extractBitLengths(closestSet, destNode);
        
        if (observedBitLengths.isEmpty()) {
            result.diagnostics = "No K-distances found";
            result.isAttackDetected = false;
            return result;
        }
        
        result.samplesAnalyzed = observedBitLengths.size();
        
        // Calculate statistics on observed data
        double[] stats = calculateStatistics(observedBitLengths);
        result.meanBitLength = stats[0];
        double stdDevObserved = stats[1];
        
        // Calculate baseline statistics for outlier detection
        double baselineMean = referenceBaseline.meanKDistance;
        double baselineStdDev = referenceBaseline.stdDevKDistance;
        double baselineMin = referenceBaseline.minBits;
        double baselineMax = referenceBaseline.maxBits;
        
        // Define normal range: baseline mean ± 2 standard deviations
        // Values outside this range are considered outliers
        double normalLowerBound = baselineMean - (2.0 * baselineStdDev);
        double normalUpperBound = baselineMean + (2.0 * baselineStdDev);
        
        // Count only LOW outliers (Sybil-like): values BELOW normal range
        // HIGH outliers (nodes that are far away) are NOT relevant for Sybil detection
        result.outlierCount = 0;
        for (int bitLength : observedBitLengths) {
            if (bitLength < normalLowerBound) {
                // This is a Sybil-like outlier (abnormally close)
                result.outlierCount++;
            }
            // Ignore if bitLength > normalUpperBound (far away is not Sybils)
        }
        
        // Calcule le poucentage d'anomalie (par rapport au nombre de noeuds présent dans le closestKNodes) 
        // => Cela évite les détections répétés d'une même attaque
        result.outlierPercentage = (double) result.outlierCount / closestKNodesSize * 100.0;
        
        // Anomaly score: normalized outlier percentage
        result.anomalyScore = result.outlierPercentage / 100.0;
        
        // Decision: attack detected if outlier percentage exceeds threshold
        result.isAttackDetected = result.outlierPercentage >= (threshold * 100.0);
        
        // Generate diagnostic message
        result.diagnostics = String.format(
            "Observed Mean=%.2f bits, Baseline Mean=%.2f bits, Sybil-like Range=[<%.1f], " +
            "Low Outliers=%d/%d (%.1f%%), Threshold=%.1f%% | Attack=%s",
            result.meanBitLength,
            baselineMean,
            normalLowerBound,
            result.outlierCount,
            result.samplesAnalyzed,
            result.outlierPercentage,
            threshold * 100.0,
            result.isAttackDetected);
        
        return result;
    }
    
    /**
     * Extract bit lengths of K distances from the closest set.
     * For each node in closestSet, calculate distance to destNode and get bitLength.
     * 
     * @param closestSet HashMap of found nodes
     * @param destNode Target node being searched
     * @return List of bit lengths (sorted)
     */
    private static List<Integer> extractBitLengths(
            HashMap<BigInteger, Boolean> closestSet,
            BigInteger destNode) {
        
        List<Integer> bitLengths = new ArrayList<>();
        
        for (BigInteger nodeId : closestSet.keySet()) {
            if (nodeId != null) {
                // Calculate XOR distance from found node to destination
                BigInteger distance = Util.distance(nodeId, destNode);
                int bitLength = distance.bitLength();
                bitLengths.add(bitLength);
            }
        }
        
        // Sort for analysis
        java.util.Collections.sort(bitLengths);
        
        return bitLengths;
    }
    
    /**
     * Calculate mean and standard deviation of bit lengths.
     * 
     * @param bitLengths List of bit length values
     * @return [mean, stdDev]
     */
    private static double[] calculateStatistics(List<Integer> bitLengths) {
        if (bitLengths.isEmpty()) {
            return new double[]{0.0, 0.0};
        }
        
        // Calculate mean
        double sum = 0;
        for (int bl : bitLengths) {
            sum += bl;
        }
        double mean = sum / bitLengths.size();
        
        // Calculate standard deviation
        double varSum = 0;
        for (int bl : bitLengths) {
            varSum += (bl - mean) * (bl - mean);
        }
        double stdDev = Math.sqrt(varSum / bitLengths.size());
        
        return new double[]{mean, stdDev};
    }
    
    /**
     * Calcule combien de recherches additionnelles lancer pour mitigation
     * basé sur l'excès d'anomalies détectées
     * 
     * Formule: M = CEIL(K × outlierPercentage / 100)
     * 
     * @param result Résultat de la détection d'anomalie
     * @return Nombre de recherches à lancer
     */
    public static int calculateSearchesToLaunch(DetectionResult result) {
        double K = KademliaCommonConfig.K;
        int searchesToLaunch = (int) Math.ceil(K * (result.outlierPercentage / 100.0));
        return Math.max(1, Math.min(searchesToLaunch, 10)); // Min 1, Max 10 recherches
    }
}

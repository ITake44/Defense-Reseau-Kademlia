package peersim.kademlia;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Control;
import peersim.core.Network;
import peersim.core.Node;

/**
 * Initializes the reference baseline for anomaly-based Sybil detection.
 * 
 * This Control runs at time=0 to compute the baseline distribution of K-distances
 * from a sample of nodes. The baseline is then used
 * for subsequent periodic detection searches.
 * 
 */
public class BaselineInitializer implements Control {
    
    /**
     * Configuration parameter for protocol
     */
    private static final String PAR_PROT = "protocol";
    
    /**
     * Configuration parameter for sample size
     */
    private static final String PAR_SAMPLE_SIZE = "sample_size";
    
    /**
     * Protocol ID
     */
    private final int pid;
    
    /**
     * Sample size for baseline computation (default: 500)
     */
    private final int sampleSize;
    
    /**
     * Target node ID for distance calculations
     */
    private BigInteger targetNodeId = new BigInteger("409281074974745890872116138270055241252539876");

    /**
     * Constructor
     * 
     * @param prefix Configuration prefix
     */
    public BaselineInitializer(String prefix) {
        pid = Configuration.getPid(prefix + "." + PAR_PROT);
        sampleSize = Configuration.getInt(prefix + "." + PAR_SAMPLE_SIZE, 500);
    }

    /**
     * Execute baseline initialization at time=0
     * 
     * @return false to indicate this control should continue running
     */
    @Override
    public boolean execute() {
        // Only execute once, at time 0
        if (CommonState.getTime() == 0) {
            System.out.println("[BASELINE-INIT] Starting baseline computation at simulation start...");
            computeBaseline();
            System.out.println("[BASELINE-INIT] Baseline computation complete. Anomaly detection is READY.");
        }
        
        return false;
    }

    /**
     * Compute the reference baseline by analyzing K-distances of normal nodes
     */
    private void computeBaseline() {
        List<Integer> bitLengths = new ArrayList<>();
        
        // Stratified sampling: sample every Nth node
        int networkSize = Network.size();
        int sampleInterval = Math.max(1, networkSize / sampleSize);
        int samplesCollected = 0;
        
        System.out.println("[BASELINE-INIT] Network size: " + networkSize);
        System.out.println("[BASELINE-INIT] Target sample size: " + sampleSize);
        System.out.println("[BASELINE-INIT] Sample interval: " + sampleInterval);
        
        // Iterate through the network with stratified sampling
        for (int i = 0; i < networkSize && samplesCollected < sampleSize; i += sampleInterval) {
            Node n = Network.get(i);
            if (n == null || !n.isUp()) continue;
            
            KademliaProtocol proto = (KademliaProtocol) n.getProtocol(pid);
            if (proto == null) continue;
            
            BigInteger queryNodeId = proto.nodeId;
            

            // Find K=20 global nearest neighbors
            BigInteger[] kNearest = findKNearestNeighborsGlobal(queryNodeId, KademliaCommonConfig.K);
            
            if (kNearest.length > 0) {
                // Collect distances to ALL K neighbors
                // This gives a rich representation of the actual distance distribution
                for (int j = 0; j < kNearest.length; j++) {
                    BigInteger distance = Util.distance(queryNodeId, kNearest[j]);
                    int bitLength = distance.bitLength();
                    bitLengths.add(bitLength);
                }
                samplesCollected++;
            }
        }
        
        System.out.println("[BASELINE-INIT] Samples collected: " + samplesCollected + " nodes sampled");
        System.out.println("[BASELINE-INIT] Total bitLength values: " + bitLengths.size() + " (= nodes × K neighbors)");
        
        // Compute reference baseline from collected bit lengths
        if (!bitLengths.isEmpty()) {
            createAndStoreBaseline(bitLengths);
        } else {
            System.err.println("[BASELINE-INIT] ERROR: No samples collected for baseline!");
        }
    }

    /**
     * Find K nearest neighbors in the global network for a query node
     * 
     * @param queryNodeId Node ID to search around
     * @param k Number of neighbors to find
     * @return Array of K nearest node IDs
     */
    private BigInteger[] findKNearestNeighborsGlobal(BigInteger queryNodeId, int k) {
        List<BigInteger> neighbors = new ArrayList<>();
        
        // Calculate distance to every node
        for (int i = 0; i < Network.size(); i++) {
            Node n = Network.get(i);
            if (n == null || !n.isUp()) continue;
            
            KademliaProtocol proto = (KademliaProtocol) n.getProtocol(pid);
            if (proto == null || proto.nodeId.equals(queryNodeId)) continue;
            
            neighbors.add(proto.nodeId);
        }
        
        // Sort by XOR distance to query node
        neighbors.sort((a, b) -> {
            BigInteger distA = Util.distance(a, queryNodeId);
            BigInteger distB = Util.distance(b, queryNodeId);
            return distA.compareTo(distB);
        });
        
        // Return K nearest
        BigInteger[] result = new BigInteger[Math.min(k, neighbors.size())];
        for (int i = 0; i < result.length; i++) {
            result[i] = neighbors.get(i);
        }
        
        return result;
    }

    /**
     * Create and store the reference baseline
     * 
     * @param bitLengths List of bit lengths collected from K-distances
     */
    private void createAndStoreBaseline(List<Integer> bitLengths) {
        int[] bits = bitLengths.stream().mapToInt(Integer::intValue).toArray();
        java.util.Arrays.sort(bits);
        
        // Calculate statistics
        double mean = bitLengths.stream().mapToInt(Integer::intValue).average().orElse(0);
        double stdDev = computeStdDev(bitLengths);
        int median = bits[bits.length / 2];
        int minBits = bits[0];
        int maxBits = bits[bits.length - 1];
        
        // DEBUG: Print distribution to analyze grouping
        System.out.println("\n[BASELINE-DEBUG] ========== BIT LENGTH DISTRIBUTION ==========");
        java.util.Map<Integer, Integer> distribution = new java.util.HashMap<>();
        for (int bit : bits) {
            distribution.put(bit, distribution.getOrDefault(bit, 0) + 1);
        }
        distribution.keySet().stream().sorted().forEach(bit -> {
            System.out.println("[BASELINE-DEBUG] bitLength=" + bit + " : " + distribution.get(bit) + " samples");
        });
        System.out.println("[BASELINE-DEBUG] Min: " + minBits + ", Max: " + maxBits + ", Mean: " + String.format("%.2f", mean));
        
        // Create direct mapping: bitLength → frequency 
        // This gives precise representation of the actual distribution
        int[] bitLengthValues = new int[distribution.size()];
        int[] bitLengthFrequencies = new int[distribution.size()];
        
        int idx = 0;
        for (Integer bitLength : distribution.keySet().stream().sorted().collect(java.util.stream.Collectors.toList())) {
            bitLengthValues[idx] = bitLength;
            bitLengthFrequencies[idx] = distribution.get(bitLength);
            idx++;
        }
        
        // Create and store reference baseline
        KademliaObserver.ReferenceBaseline ref = new KademliaObserver.ReferenceBaseline();
        ref.meanKDistance = mean;
        ref.stdDevKDistance = stdDev;
        ref.medianKDistance = median;
        ref.minBits = minBits;
        ref.maxBits = maxBits;
        ref.bitLengthValues = bitLengthValues;
        ref.bitLengthFrequencies = bitLengthFrequencies;
        ref.totalSamples = bitLengths.size();
        ref.isReady = true;
        
        // Assign to static variable (shared by all nodes)
        KademliaObserver.referenceBaseline = ref;
        
        // Log the baseline summary (distribution already logged above)
        System.out.println("\n[BASELINE-INIT] ========== BASELINE READY ==========");
        System.out.println("[BASELINE-INIT] Mean K-distance: 2^" + String.format("%.2f", mean));
        System.out.println("[BASELINE-INIT] StdDev: " + String.format("%.3f", stdDev) + " bits");
        System.out.println("[BASELINE-INIT] Median: 2^" + median);
        System.out.println("[BASELINE-INIT] Range: 2^" + minBits + " to 2^" + maxBits);
        System.out.println("[BASELINE-INIT] Samples: " + bitLengths.size());
        System.out.println("[BASELINE-INIT] Distinct bitLengths: " + bitLengthValues.length);
        System.out.println("[BASELINE-INIT] ========================================\n");
    }

    /**
     * Compute standard deviation
     * 
     * @param values List of values
     * @return Standard deviation
     */
    private double computeStdDev(List<Integer> values) {
        if (values.isEmpty()) return 0.0;
        
        double mean = values.stream().mapToInt(Integer::intValue).average().orElse(0);
        double variance = values.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average()
            .orElse(0);
        
        return Math.sqrt(variance);
    }
}

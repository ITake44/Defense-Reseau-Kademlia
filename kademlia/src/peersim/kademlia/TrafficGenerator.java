package peersim.kademlia;

import java.math.BigInteger;
import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Control;
import peersim.core.Network;
import peersim.core.Node;
import peersim.edsim.EDSimulator;

/**
 * This control generates random search traffic from nodes to random destination node.
 * 
 * @author Daniele Furlan, Maurizio Bonani
 * @version 1.0
 */

// ______________________________________________________________________________________________
public class TrafficGenerator implements Control {

	// ______________________________________________________________________________________________
	/**
	 * MSPastry Protocol to act
	 */
	private final static String PAR_PROT = "protocol";

	/**
	 * Configuration parameter for Sybil target ID
	 */
	private final static String PAR_TARGET_ID = "sybil_target";
	
	/**
	 * Configuration parameter for detection search period
	 * (periodic detection search triggered every N calls)
	 */
	private final static String PAR_DETECTION_PERIOD = "detection_period";

    // Target NodeId for Sybil 
    private BigInteger targetNodeId = null;

	/**
	 * MSPastry Protocol ID to act
	 */
	private final int pid;
	
	/**
	 * Period (in number of execute() calls) for periodic detection searches
	 * Default: 100 (every 100 calls, one detection search)
	 */
	private final int detectionPeriod;
	
	/**
	 * Call counter for periodic detection triggering
	 */
	private long callCounter = 0;
	
	/**
	 * Exploration candidates discovered during Phase 1 discovery
	 * Shared with KademliaProtocol for phase coordination
	 */
	public static java.util.HashSet<BigInteger> explorationCandidates = new java.util.HashSet<>();
	
	/**
	 * Flag indicating if discovery phase is complete
	 * false = still in Phase 1 (discovery)
	 * true = in Phase 2 (exploration)
	 */
	public static boolean discoveryComplete = false;

	// ______________________________________________________________________________________________
    public TrafficGenerator(String prefix) {
        pid = Configuration.getPid(prefix + "." + PAR_PROT);
        detectionPeriod = Configuration.getInt(prefix + "." + PAR_DETECTION_PERIOD, 100);
        
        // Récupérer la cible Sybil si elle existe
        String targetIdStr = Configuration.getString(prefix + ".sybil_target", "");
        if (!targetIdStr.isEmpty()) {
            try {
                this.targetNodeId = new BigInteger(targetIdStr);
            } catch (Exception e) {
                System.err.println("Warning: Invalid sybil_target in configuration");
                this.targetNodeId = null;
            }
        }
    }

	// ______________________________________________________________________________________________
	/**
	 * generates a random find node message, by selecting randomly the destination.
	 * 
	 * @return Message
	 */
	private Message generateFindNodeMessage() {
		Message m = Message.makeFindNode("Automatically Generated Traffic");
		m.timestamp = CommonState.getTime();

		// existing active destination node
		Node n = Network.get(CommonState.r.nextInt(Network.size()));
		while (!n.isUp()) {
			n = Network.get(CommonState.r.nextInt(Network.size()));
		}
		m.dest = ((KademliaProtocol) (n.getProtocol(pid))).nodeId;

		return m;
	}

	// ______________________________________________________________________________________________
	/**
     * Generates a find node message targeting the Sybil target value.
     * This is used to test if the target value is censored by Sybil nodes.
     * 
     * @return Message
     */
    private Message generateTargetSearchMessage() {
        Message m = Message.makeFindNode("Target Search");
        m.timestamp = CommonState.getTime();
        
        // Set destination to the target NodeId
        if (this.targetNodeId != null) {
            m.dest = this.targetNodeId;
        } else {
            // Fallback to random search if target not set
            return generateFindNodeMessage();
        }
        
        return m;
    }

    // ______________________________________________________________________________________________
    /**
     * PHASE 1: Discovery message - searches for the exact Sybil target
     * Used only once to populate explorationCandidates with nodes around target
     * 
     * @return Message searching for targetNodeId
     */
    private Message generateDiscoveryMessage() {
        Message m = Message.makeFindNode("Periodic Detection Search");
        m.timestamp = CommonState.getTime();
        
        if (this.targetNodeId != null) {
            m.dest = this.targetNodeId;
        } else {
            Node n = Network.get(CommonState.r.nextInt(Network.size()));
            while (!n.isUp()) {
                n = Network.get(CommonState.r.nextInt(Network.size()));
            }
            m.dest = ((KademliaProtocol) (n.getProtocol(pid))).nodeId;
        }
        
        return m;
    }

    // ______________________________________________________________________________________________
    /**
     * PHASE 2: Exploration message - searches directly toward exploration candidates
     * Uses exploration candidates discovered in Phase 1 as search targets
     * 
     * @return Message searching for each exploration candidate in turn
     */
    private Message generateExplorationMessage() {
        Message m = Message.makeFindNode("Periodic Detection Search");
        m.timestamp = CommonState.getTime();
        
        // Get a random candidate directly
        if (explorationCandidates.isEmpty()) {
            // Fallback if no candidates yet
            m.dest = this.targetNodeId;
        } else {
            BigInteger[] candidates = explorationCandidates.toArray(new BigInteger[0]);
            m.dest = candidates[CommonState.r.nextInt(candidates.length)];
        }
        
        return m;
    }

    // ______________________________________________________________________________________________
    /**
     * Generates a periodic detection search message.
     * PHASE 1: If discovery not complete, search for exact target
     * PHASE 2: If discovery complete, search for exploration candidates
     * 
     * @return Message
     */
    private Message generatePeriodicDetectionMessage() {
        if (!discoveryComplete) {
            // PHASE 1: Discovery - find nodes around target
            return generateDiscoveryMessage();
        } else {
            // PHASE 2: Exploration - search toward discovery candidates
            return generateExplorationMessage();
        }
    }


    // ______________________________________________________________________________________________
    /**
     * Every call of this control generates and sends a message.
     * Message type is decided periodically:
     * - Every detectionPeriod calls: M parallel Periodic Detection Searches
     * - Other calls: 20% Target Search (Sybil target), 80% Random search
     * 
     * @return boolean
     */
    public boolean execute() {
        Node start;
        do {
            start = Network.get(CommonState.r.nextInt(Network.size()));
        } while ((start == null) || (!start.isUp()));

        // Increment call counter
        callCounter++;
        
        // Decide message type based on periodic detection period
        Message message;
        
        // Every detectionPeriod calls, trigger periodic detection searches
        if (callCounter % detectionPeriod == 0) {
            // PHASE 1: First detection cycle = discovery
            if (!discoveryComplete) {
                // Send single discovery message to find initial candidates
                Message discovery = generateDiscoveryMessage();
                EDSimulator.add(0, discovery, start, pid);
            } 
            // PHASE 2: Subsequent cycles = exploration toward candidates
            else {
                // On fixe le nombre de messages d'exploration à envoyer en parallèle à 3
                for (int i = 0; i < 3; i++) {
                    Message exploration = generateExplorationMessage();
                    EDSimulator.add(0, exploration, start, pid);
                }
            }
        } else {
            // Otherwise, choose between Target Search and Random search
            if (this.targetNodeId != null && CommonState.r.nextDouble() < 0.2) {
                // 20% Generate a targeted search toward the Sybil target
                message = generateTargetSearchMessage();
            } else {
                // 80% Generate a random search
                message = generateFindNodeMessage();
            }
            // Send single message
            EDSimulator.add(0, message, start, pid);
        }

        return false;
    }

	// ______________________________________________________________________________________________

} // End of class

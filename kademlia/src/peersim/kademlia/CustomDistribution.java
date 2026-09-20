package peersim.kademlia;

import java.math.BigInteger;

import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Network;
import peersim.core.Node;

/**
 * This control initializes the whole network (that was already created by peersim) assigning a unique NodeId, randomly generated,
 * to every node. Sybil nodes are assigned IDs close to the target.
 * 
 * @author Daniele Furlan, Maurizio Bonani
 * @version 1.0
 */
public class CustomDistribution implements peersim.core.Control {

	private static final String PAR_PROT = "protocol";
	private static final String PAR_SYBIL_COUNT = "sybil_count";
	private static final String PAR_SYBIL_TARGET = "sybil_target";
	private static final String PAR_PROXIMITY_BITS = "proximity_bits";
	private int protocolID;
	private UniformRandomGenerator urg;

	private BigInteger targetNodeId;
	private int numSybils;
	private int proximityBits;

	public CustomDistribution(String prefix) {
		protocolID = Configuration.getPid(prefix + "." + PAR_PROT);
		urg = new UniformRandomGenerator(KademliaCommonConfig.BITS, CommonState.r);
		
		// Lire les paramètres de configuration
		numSybils = Configuration.getInt(prefix + "." + PAR_SYBIL_COUNT, 50);
		proximityBits = Configuration.getInt(prefix + "." + PAR_PROXIMITY_BITS, 20);
		
		// Lire la cible et la convertir en BigInteger
		String targetStr = Configuration.getString(prefix + "." + PAR_SYBIL_TARGET, "409281074974745890872116138270055241252539876");
		targetNodeId = new BigInteger(targetStr);
	}

	/**
	 * Génère un ID de nœud proche du targetNodeId en utilisant la métrique XOR de Kademlia.
	 * 
	 * @return BigInteger un ID proche du targetNodeId
	 */
	private BigInteger generateCloseNodeId() {
		if (targetNodeId == null) {
			return urg.generate();
		}
		
		// Générer un nombre aléatoire petit pour représenter la distance XOR
		BigInteger randomOffset = new BigInteger(proximityBits, CommonState.r);
		
		// La distance XOR garantit la proximité dans l'espace Kademlia
		BigInteger closeNodeId = targetNodeId.xor(randomOffset);
		
		// S'assurer que l'ID reste dans l'espace 0..2^BITS
		BigInteger maxNodeId = BigInteger.ONE.shiftLeft(KademliaCommonConfig.BITS).subtract(BigInteger.ONE);
		if (closeNodeId.compareTo(maxNodeId) > 0) {
			closeNodeId = closeNodeId.and(maxNodeId);
		}
		
		return closeNodeId;
	}

	/**
	 * Scan over the nodes in the network and assign a randomly generated NodeId in the space 0..2^BITS, where BITS is a parameter
	 * from the kademlia protocol (usually 160)
	 * 
	 * @return boolean always false
	 */
	public boolean execute() {
		// Sélectionner aléatoirement numSybils nœuds et les marquer comme Sybils
		int sz = Network.size();
		int count = 0;
		
		// Marquer les Sybils aléatoirement
		if (numSybils > 0) {
			System.out.println("=== Marquage de " + numSybils + " noeuds comme Sybils ===");
			while (count < numSybils && count < sz) {
				int randomIndex = CommonState.r.nextInt(sz);
				Node node = Network.get(randomIndex);
				KademliaProtocol proto = ((KademliaProtocol) (node.getProtocol(protocolID)));
				
				if (!proto.isSybil()) {
					proto.setSybil();
					count++;
				}
			}
		}
		
		// Assigner les IDs
		BigInteger tmp;
		for (int i = 0; i < sz; ++i) {
			KademliaProtocol proto = ((KademliaProtocol) (Network.get(i).getProtocol(protocolID)));
			
			if (proto.isSybil()) {
				// Les nœuds Sybils reçoivent un ID proche de la cible
				tmp = generateCloseNodeId();
				proto.setNodeId(tmp);
				
				// Afficher la distance seulement si la cible est définie
				if (targetNodeId != null) {
					BigInteger distance = Util.distance(tmp, targetNodeId);
					System.out.println("Sybil NodeId: " + tmp + " Distance XOR: " + distance);
				} else {
					System.out.println("Sybil NodeId: " + tmp);
				}
			} else {
				// Les nœuds normaux reçoivent un ID aléatoire
				tmp = urg.generate();
				proto.setNodeId(tmp);
			}
		}

		return false;
	}

}

package peersim.kademlia;

import java.util.Comparator;
import java.math.BigInteger;

import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Network;
import peersim.core.Node;
import peersim.transport.Transport;

/**
 * Initialization class that performs the bootsrap filling the k-buckets of all initial nodes.<br>
 * In particular, it adds a number of random neighbors and a number of close neighbors (by ID proximity) to each node's routing table.
 * 
 */
public class StateBuilder implements peersim.core.Control {

	private static final String PAR_PROT = "protocol";
	private static final String PAR_TRANSPORT = "transport";

	private String prefix;
	private int kademliaid;
	private int transportid;

	public StateBuilder(String prefix) {
		this.prefix = prefix;
		kademliaid = Configuration.getPid(this.prefix + "." + PAR_PROT);
		transportid = Configuration.getPid(this.prefix + "." + PAR_TRANSPORT);
	}

	// ______________________________________________________________________________________________
	public final KademliaProtocol get(int i) {
		return ((KademliaProtocol) (Network.get(i)).getProtocol(kademliaid));
	}

	// ______________________________________________________________________________________________
	public final Transport getTr(int i) {
		return ((Transport) (Network.get(i)).getProtocol(transportid));
	}

	// ______________________________________________________________________________________________
	public static void o(Object o) {
		System.out.println(o);
	}

	// ______________________________________________________________________________________________
	public boolean execute() {

		// Sort the network by nodeId (Ascending)
		Network.sort(new Comparator<Node>() {

			public int compare(Node o1, Node o2) {
				Node n1 = (Node) o1;
				Node n2 = (Node) o2;
				KademliaProtocol p1 = (KademliaProtocol) (n1.getProtocol(kademliaid));
				KademliaProtocol p2 = (KademliaProtocol) (n2.getProtocol(kademliaid));
				return Util.put0(p1.nodeId).compareTo(Util.put0(p2.nodeId));
			}

		});

		int sz = Network.size();
		
		// Calculate number of neighbors based on network size to ensure network maturity
		int numRandomNeighbors = Math.max(100, Math.min(sz / 30, 1000));  // 5% of network, 166 for 5000
		int numCloseNeighbors = Math.max(50, Math.min(sz / 30, 300));     // 5% of network, 166 for 5000
		
		System.out.println("[StateBuilder] Network size: " + sz);
		System.out.println("[StateBuilder] Random neighbors per node: " + numRandomNeighbors);
		System.out.println("[StateBuilder] Close neighbors per node: " + numCloseNeighbors);

		// for every node take random neighbors and add to k-bucket of it
		for (int i = 0; i < sz; i++) {
			Node iNode = Network.get(i);
			KademliaProtocol iKad = (KademliaProtocol) (iNode.getProtocol(kademliaid));

			for (int k = 0; k < numRandomNeighbors; k++) {
				KademliaProtocol jKad = (KademliaProtocol) (Network.get(CommonState.r.nextInt(sz)).getProtocol(kademliaid));
				iKad.routingTable.addNeighbour(jKad.nodeId);
			}
		}

		// add close neighbors (by ID proximity)
		for (int i = 0; i < sz; i++) {
			Node iNode = Network.get(i);
			KademliaProtocol iKad = (KademliaProtocol) (iNode.getProtocol(kademliaid));

			int start = i;
			if (i > sz - numCloseNeighbors) {
				start = sz - numCloseNeighbors / 2;
			}
			for (int k = 0; k < numCloseNeighbors; k++) {
				start = start++;
				if (start > 0 && start < sz) {
					KademliaProtocol jKad = (KademliaProtocol) (Network.get(start++).getProtocol(kademliaid));
					iKad.routingTable.addNeighbour(jKad.nodeId);
				}
			}
		}

		return false;

	} // end execute()
}
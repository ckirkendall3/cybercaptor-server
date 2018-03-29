package org.fiware.cybercaptor.server.scoring.math;

import org.fiware.cybercaptor.server.scoring.types.Arc;
import org.fiware.cybercaptor.server.scoring.types.Graph;
import org.fiware.cybercaptor.server.scoring.types.Vertex;
import org.fiware.cybercaptor.server.scoring.types.VertexType;
import org.junit.Test;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;


/**
 * Class to test the topology.
 *
 * @author François -Xavier Aguessy
 */
public class AttackPathsTest {

    /**
     * Test hosts.
     */
    @Test
    public void testMergeGraphs() {
        Graph successor = createGraph(20000, 4000, 0);
        Graph predecessor = createGraph(10000, 2000, 4000);

        long millis = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            Set<Arc> successorArcs = new HashSet<>(successor.getArcs());
            Set<Arc> predecessorArcs = new HashSet<>(predecessor.getArcs());
            Map<Integer, Vertex> successorVertices = new HashMap<>(successor.getVertexMap());
            Map<Integer, Vertex> predecessorVertices = new HashMap<>(predecessor.getVertexMap());
            Graph.mergeGraphs(Arrays.asList(
                    new Graph(successorArcs, successorVertices),
                    new Graph(predecessorArcs, predecessorVertices)));

        }
        System.out.print("\nMerge Time: " + (System.currentTimeMillis() - millis));
    }

    private Graph createGraph(int numArcs, int numVertices, int startId) {
        Map<Integer, Vertex> vertices = new HashMap<>();
        Set<Arc> arcs = new HashSet<>();

        int endId = startId + numVertices + 1;
        for (int i = startId; i < endId; i++) {
            vertices.put(i, new Vertex(i, "fact" + i, i, VertexType.LEAF));
        }

        for (int i = 0; i < numArcs; i++) {
            int source = ThreadLocalRandom.current().nextInt(startId, endId);
            int destination = ThreadLocalRandom.current().nextInt(startId, endId);
            arcs.add(new Arc(source, destination));
        }
        return new Graph(arcs, vertices);
    }
}

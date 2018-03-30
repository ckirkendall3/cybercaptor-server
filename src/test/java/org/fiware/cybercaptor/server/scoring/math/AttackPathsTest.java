package org.fiware.cybercaptor.server.scoring.math;

import org.fiware.cybercaptor.server.attackgraph.ImpactMetric;
import org.fiware.cybercaptor.server.attackgraph.MulvalAttackGraph;
import org.fiware.cybercaptor.server.scoring.types.Arc;
import org.fiware.cybercaptor.server.scoring.types.Graph;
import org.fiware.cybercaptor.server.scoring.types.Vertex;
import org.fiware.cybercaptor.server.scoring.types.VertexType;
import org.junit.Test;

import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Class to test the topology.
 *
 * @author François -Xavier Aguessy
 */
public class AttackPathsTest {

    private static int loopCount = 1;
    /**
     * Test attack graph evaluation
     */
    @Test
    public void testAttackGraphEval() throws Exception {
        long startMillis = System.nanoTime();
        for (int loop = 0; loop < loopCount; loop++ ) {
            String path =
                    Paths.get(this.getClass().getClassLoader().getResource("AttackGraph.xml").toURI()).toFile().getAbsolutePath();

            //System.out.println(System.currentTimeMillis() + ": Loading mulval attack graph from file");
            MulvalAttackGraph mulvalAttackGraph = new MulvalAttackGraph();
            mulvalAttackGraph.loadFromFile(path);

            System.out.println(System.currentTimeMillis() + " (NEW): Start attack path generation");
            Arc[] ArcsTable = new Arc[mulvalAttackGraph.arcs.size()];
            Vertex[] VerticesTable = new Vertex[mulvalAttackGraph.getNumberOfVertices()];

            int i = 0;
            //System.out.println(System.currentTimeMillis() + ": Setup attack path graph");
            for (Integer key : mulvalAttackGraph.vertices.keySet()) {
                org.fiware.cybercaptor.server.attackgraph.Vertex vertex = mulvalAttackGraph.vertices.get(key);
                VerticesTable[i] = new Vertex(-1, "EOF", -1, VertexType.LEAF);
                VerticesTable[i].setID(vertex.id);
                VerticesTable[i].setFact(vertex.fact.factString);
                VerticesTable[i].setMulvalMetric(vertex.mulvalMetric);
                VerticesTable[i].setType(VertexType.valueOf(vertex.type.toString().toUpperCase()));
                ImpactMetric[] impactMetrics = new ImpactMetric[vertex.impactMetrics.size()];
                for (int j = 0; j < vertex.impactMetrics.size(); j++) {
                    impactMetrics[j] = vertex.impactMetrics.get(j);
                }
                VerticesTable[i].setImpactMetrics(impactMetrics);
                i++;
            }

            for (int j = 0; j < mulvalAttackGraph.arcs.size(); j++) {
                org.fiware.cybercaptor.server.attackgraph.Arc arc = mulvalAttackGraph.arcs.get(j);
                ArcsTable[j] = new Arc(-1, -1);
                ArcsTable[j].setSource(arc.destination.id);
                ArcsTable[j].setDestination(arc.source.id);
            }

            Graph graph = new Graph(ArcsTable, VerticesTable);
            Vertex[] TargetSet = Graph.getVerticesOnTypeAndFact(VerticesTable, VertexType.OR);

            //System.out.println(System.currentTimeMillis() + ": Generate Attack Paths");
            Graph[] result = AttackPaths.main(TargetSet, graph); //Disabled following the test launch of attack path algorithm.

            //System.out.println(System.currentTimeMillis() + ": Scoring Attack Paths");
            ScoringFormulas formulas = new ScoringFormulas();
            double scoreAttackGraph = formulas.MinMax(formulas.globalScore(graph), 1);
            //System.out.println(System.currentTimeMillis() + ": Attack path score: " + scoreAttackGraph);

            int count = 0;
            for (Graph attackPath : result) {
                if ( attackPath.getVertexMap().size() > 3) {
                    count++;
                }
                //System.out.println(System.currentTimeMillis() + ": AttackPath(arcs:" + attackPath.getArcs().size() +
                //        ", vertices:" + attackPath.getVertexMap().size() + ")");
            }
            System.out.println(System.currentTimeMillis() + " (NEW): Number of attack paths - " + count);
        }
        System.out.println("(NEW) Total time with " + loopCount + " loops: " + (System.nanoTime() - startMillis));
    }

    /**
     * Test attack graph evaluation
     */
    @Test
    public void testAttackGraphEval2() throws Exception {
        long startMillis = System.nanoTime();
        for (int loop = 0; loop < loopCount; loop++ ) {
            String path =
                    Paths.get(this.getClass().getClassLoader().getResource("AttackGraph.xml").toURI()).toFile().getAbsolutePath();

            //System.out.println(System.currentTimeMillis() + ": Loading mulval attack graph from file");
            MulvalAttackGraph mulvalAttackGraph = new MulvalAttackGraph();
            mulvalAttackGraph.loadFromFile(path);

            System.out.println(System.currentTimeMillis() + ": Start attack path generation");
            Arc[] ArcsTable = new Arc[mulvalAttackGraph.arcs.size()];
            Vertex[] VerticesTable = new Vertex[mulvalAttackGraph.getNumberOfVertices()];

            int i = 0;
            //System.out.println(System.currentTimeMillis() + ": Setup attack path graph");
            for (Integer key : mulvalAttackGraph.vertices.keySet()) {
                org.fiware.cybercaptor.server.attackgraph.Vertex vertex = mulvalAttackGraph.vertices.get(key);
                VerticesTable[i] = new Vertex(-1, "EOF", -1, VertexType.LEAF);
                VerticesTable[i].setID(vertex.id);
                VerticesTable[i].setFact(vertex.fact.factString);
                VerticesTable[i].setMulvalMetric(vertex.mulvalMetric);
                VerticesTable[i].setType(VertexType.valueOf(vertex.type.toString().toUpperCase()));
                ImpactMetric[] impactMetrics = new ImpactMetric[vertex.impactMetrics.size()];
                for (int j = 0; j < vertex.impactMetrics.size(); j++) {
                    impactMetrics[j] = vertex.impactMetrics.get(j);
                }
                VerticesTable[i].setImpactMetrics(impactMetrics);
                i++;
            }

            for (int j = 0; j < mulvalAttackGraph.arcs.size(); j++) {
                org.fiware.cybercaptor.server.attackgraph.Arc arc = mulvalAttackGraph.arcs.get(j);
                ArcsTable[j] = new Arc(-1, -1);
                ArcsTable[j].setSource(arc.destination.id);
                ArcsTable[j].setDestination(arc.source.id);
            }

            Graph graph = new Graph(ArcsTable, VerticesTable);
            Vertex[] TargetSet = Graph.getVerticesOnTypeAndFact(VerticesTable, VertexType.OR);

            //System.out.println(System.currentTimeMillis() + ": Generate Attack Paths");
            Graph[] result = AttackPaths.main2(TargetSet, graph); //Disabled following the test launch of attack path algorithm.

            //System.out.println(System.currentTimeMillis() + ": Scoring Attack Paths");
            ScoringFormulas formulas = new ScoringFormulas();
            double scoreAttackGraph = formulas.MinMax(formulas.globalScore(graph), 1);
            //System.out.println(System.currentTimeMillis() + ": Attack path score: " + scoreAttackGraph);

            int count = 0;
            for (Graph attackPath : result) {
                if ( attackPath.getVertexMap().size() > 3) {
                    count++;
                }
                //System.out.println(System.currentTimeMillis() + ": AttackPath(arcs:" + attackPath.getArcs().size() +
                //", vertices:" + attackPath.getVertexMap().size() + ")");
            }
            System.out.println(System.currentTimeMillis() + ": Number of attack paths - " + count);
        }
        System.out.println("Total time with " + loopCount + " loops: " + (System.nanoTime() - startMillis));
    }
    /**
     * Test merging.
     */
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

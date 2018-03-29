/****************************************************************************************
 * This file is part of FIWARE CyberCAPTOR,                                             *
 * instance of FIWARE Cyber Security Generic Enabler                                    *
 * Copyright (C) 2012-2015  Thales Services S.A.S.,                                     *
 * 20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE                           *
 *                                                                                      *
 * FIWARE CyberCAPTOR is free software; you can redistribute                            *
 * it and/or modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 3 of the License,       *
 * or (at your option) any later version.                                               *
 *                                                                                      *
 * FIWARE CyberCAPTOR is distributed in the hope                                        *
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied           *
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                                         *
 *                                                                                      *
 * You should have received a copy of the GNU General Public License                    *
 * along with FIWARE CyberCAPTOR.                                                       *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/
package org.fiware.cybercaptor.server.scoring.types;

import java.util.*;

/**
 * Class used to represent a graph
 *
 * @author K. M.
 */
public class Graph {

    /**
     * The arcs of the graph
     */
    private Set<Arc> Arcs;

    /**
     * The vertices of the graph
     */
    private Map<Integer, Vertex> VertexMap;

    /**
     * Instantiates a new Graph.
     *
     * @param arcs     the arcs
     * @param vertices the vertices
     */
    public Graph(Arc[] arcs, Vertex[] vertices) {
        Arcs = new HashSet<>(Arrays.asList(arcs));
        VertexMap = new HashMap<>();
        for (Vertex vertex : vertices)
        {
            VertexMap.put(vertex.getID(), vertex);
        }
    }

    /**
     * Instantiates a new Graph.
     *
     * @param arcs     the arcs
     * @param vertexMap the vertices
     */
    public Graph(Set<Arc> arcs, Map<Integer, Vertex> vertexMap) {
        Arcs = arcs;
        VertexMap = vertexMap;
    }

    /**
     * Get vertices on type and fact.
     *
     * @param vertices the vertices
     * @param type     the type
     * @return the vertex [ ]
     */
    public static Vertex[] getVerticesOnTypeAndFact(Vertex[] vertices, VertexType type) {
        int counter = 0;
        Vertex[] result = null;
        //the first for loop is to get the cardinality of the query result
        for (Vertex vertex : vertices) {
            if (vertex.getType().equals(type) && vertex.getFact().startsWith("execCode")) {
                counter++;
            }
        }
        if (counter != 0) {
            result = new Vertex[counter];
            counter = 0;
            for (Vertex vertex : vertices) {
                if (vertex.getType().equals(type) && vertex.getFact().startsWith("execCode")) {
                    result[counter] = vertex;
                    counter++;
                }
            }
        }
        return result;
    }

    /**
     * Get ingoing arcs number.
     *
     * @param arcs     the arcs
     * @param vertexID the vertex iD
     * @return the double
     */
    public static int getIngoingArcsNumber(Arc[] arcs, int vertexID) {
        int counter = 0;
        for (Arc arc : arcs) {
            if (arc.getSource() == vertexID) {
                counter++;
            }
        }

        return counter;
    }

    /**
     * Get outgoing arcs number.
     *
     * @param arcs     the arcs
     * @param vertexID the vertex iD
     * @return the double
     */
    public static int getOutgoingArcsNumber(Arc[] arcs, int vertexID) {
        int counter = 0;
        for (Arc arc : arcs) {
            if (arc.getDestination() == vertexID) {
                counter++;
            }
        }

        return counter;
    }

    /**
     * Get vertices on type.
     *
     * @param vertices the vertices
     * @param type     the type
     * @return the vertex [ ]
     */
    public static Vertex[] getVerticesOnType(Vertex[] vertices, VertexType type) {
        int counter = 0;
        Vertex[] result = null;
        //the first for loop is to get the cardinality of the query result
        for (Vertex vertex : vertices) {
            //System.out.println("i:"+i);
            if (vertex.getType().equals(type)) {
                counter++;
            }
        }
        if (counter != 0) {
            result = new Vertex[counter];
            counter = 0;
            for (Vertex vertex : vertices) {
                if (vertex.getType().equals(type)) {
                    result[counter] = vertex;
                    counter++;
                }
            }
        }
        return result;
    }

    /**
     * Create an atomic graph from two vertices
     *
     * @param V a vertex
     * @param D a vertex
     * @return the new graph
     */
    private static Graph createAtomicGraph(Vertex V, Vertex D) {
        Map<Integer, Vertex> vertices = new HashMap<>();
        vertices.put(V.getID(), V);
        vertices.put(D.getID(), D);
        Set<Arc> arcs = new HashSet<>();
        arcs.add(new Arc(V.getID(), D.getID()));
        return new Graph(arcs, vertices);
    }

    /**
     * Merge two graphs in a new graph
     *
     * @param graphs list of graphs to merge
     * @return the merged graph
     */
    public static Graph mergeGraphs(List<Graph> graphs) {
        Set<Arc> arcs = new HashSet<>();
        Map<Integer, Vertex> vertices = new HashMap<>();

        for ( Graph graph : graphs ) {
            if ( graph != null ) {
                arcs.addAll(graph.getArcs());
                vertices.putAll(graph.getVertexMap());
            }
        }

        return new Graph(arcs, vertices);
    }

    /**
     * Get arcs.
     *
     * @return the arcs
     */
    public Set<Arc> getArcs() {
        return Arcs;
    }


    public Map<Integer, Vertex> getVertexMap() {
        return VertexMap;
    }

    /**
     * Loops through all the arcs and configures the predecessors for all the
     * vertices and generates the graphs for nodes close to the edges (LEAF).
     */
    public void preProcessGraph() {

        for (Arc arc : Arcs) {
            Vertex source = VertexMap.get(arc.getSource());
            Vertex destination = VertexMap.get(arc.getDestination());

            if ( source.getType() != destination.getType() ) {
                source.addPredecessor(destination);

                // Create the atomic graph for this arc
                Graph atomicGraph = createAtomicGraph(source, destination);
                source.addPredecessorAtomicGraph(destination.getID(), atomicGraph);

                // Create the successor graphs for the leaf nodes for optimization
                if (destination.getType().equals(VertexType.LEAF)) {
                    destination.addSuccessorGraph(source.getID(), atomicGraph);
                }
            }
        }

        // This is an optimization to see if we can generate successor graphs for inner nodes close to the leaves.
        for (int i = 0; i < 3; i++) {
            for (Vertex vertex : VertexMap.values()) {
                if ( vertex.getType().equals(VertexType.LEAF) || vertex.getPredecessorsGraph() != null ) {
                    // Already optimized
                    continue;
                }

                // Walk through the predecessors and see if they all have successor graphs for this node.
                boolean complete = true;
                List<Graph> childGraphs = new ArrayList<>();
                for (Vertex predecessor : vertex.getPredecessors()) {
                    if (predecessor.getType() != vertex.getType()) {
                        Map<Integer, Graph> predecessorSuccessorGraphs = predecessor.getSuccessorGraphs();
                        Graph predecessorsGraph = predecessor.getPredecessorsGraph();
                        Graph successorGraph = predecessorSuccessorGraphs.get(vertex.getID());

                        if ( successorGraph == null ) {
                            if (predecessorsGraph != null) {
                                if (predecessorSuccessorGraphs.containsKey(vertex.getID())) {
                                    continue;
                                }

                                successorGraph = mergeGraphs(Arrays.asList(
                                        vertex.getPredecessorAtomicGraphs().get(predecessor.getID()),
                                        predecessorsGraph));

                                // Add successor graph to the predecessors
                                predecessorSuccessorGraphs.put(vertex.getID(), successorGraph);
                                childGraphs.add(successorGraph);
                            } else {
                                complete = false;
                            }
                        }
                        else {
                            childGraphs.add(successorGraph);
                        }
                    }
                }

                if (complete) {
                    // Merge all the success graphs together.
                    vertex.setPredecessorsGraph(mergeGraphs(childGraphs));
                }
            }
        }
    }
}

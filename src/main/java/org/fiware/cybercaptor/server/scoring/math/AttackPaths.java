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
package org.fiware.cybercaptor.server.scoring.math;

import org.fiware.cybercaptor.server.scoring.types.Arc;
import org.fiware.cybercaptor.server.scoring.types.Graph;
import org.fiware.cybercaptor.server.scoring.types.Vertex;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Class used to represent an attack path
 *
 * @author K. M.
 */
public class AttackPaths {

    /**
     * Test if an element is in the set
     *
     * @param Element the element to search
     * @param Set     the set
     * @return 0 if the element is in the set, else 1
     */
    public static int existsInSet(double Element, double[] Set) {
        //0 exists, 1 does not exist
        for (double aSet : Set) {
            if (Element == aSet) {
                return 0;
            }
        }
        return 1;
    }

    /**
     * Test if an arc is in the set
     *
     * @param Element the arc to search
     * @param Set     the set
     * @return 0 if the arc is in the set, else 1
     */
    public static int existsInSet(Arc Element, Arc[] Set) {
        //0 exists, 1 does not exist
        for (Arc aSet : Set) {
            if (Element.getSource() == aSet.getSource() && Element.getDestination() == aSet.getDestination()) {
                return 0;
            }
        }
        return 1;
    }

    /**
     * Explore the attack path = generate the attack paths
     *
     * @param Targets     the targets nodes in the attack graph
     * @param AttackGraph the attack graph
     * @return the list of attack paths
     */
    public static Graph[] main(Vertex[] Targets, Graph AttackGraph) {

        if (Targets != null) {
            AttackGraph.getPredecessors();
            Graph[] GraphTable = new Graph[Targets.length];
            Arrays.parallelSetAll(GraphTable, i -> exploreAttackPath2(Targets[i], null, AttackGraph));
            return GraphTable;
        } else {
            return null;
        }
    }

    /**
     * Create an atomic graph from two vertices
     *
     * @param V a vertex
     * @param D a vertex
     * @return the new graph
     */
    public static Graph createAtomicGraph(Vertex V, Vertex D) {
        Vertex[] BufferVertices = new Vertex[2];
        BufferVertices[0] = V;
        BufferVertices[1] = D;
        Arc[] BufferArcs = new Arc[1];
        Arc BufferArc = new Arc(V.getID(), D.getID());
        BufferArcs[0] = BufferArc;
        return new Graph(BufferArcs, BufferVertices);
    }

    /**
     * Explore the attack path from node V
     *
     * @param V         the starting vertex
     * @param Forbidden the list of forbidden vertices
     * @param graph     the attack graph
     * @return the created attack path
     */
    public static Graph exploreAttackPath2(Vertex V, HashSet<Integer> Forbidden, Graph graph) {
        Vertex LEAFVertex = new Vertex(0, "", 0.0, "LEAF");
        Vertex ORVertex = new Vertex(0, "", 0.0, "OR");
        Vertex ANDVertex = new Vertex(0, "", 0.0, "AND");
        Graph Result = null;

        List<Vertex> predecessors = V.getPredecessors();
        if (V.getType().equals(ORVertex.getType()) && Forbidden == null) {
            Forbidden = new HashSet<>();
            Forbidden.add(V.getID());
        }
        if (V.getType().equals(ANDVertex.getType())) {
            if (predecessors != null) {
                List<Graph> Buffers = new ArrayList<>();
                for (Vertex D : predecessors) {
                    if (D != null) {
                        if (D.getType().equals(LEAFVertex.getType())) {
                            Buffers.add(createAtomicGraph(V, D));
                        } else if (D.getType().equals(ORVertex.getType())) {
                            if (!Forbidden.contains(D.getID())) {
                                if (Forbidden == null) {
                                    Forbidden = new HashSet<>();
                                    Forbidden.add(D.getID());
                                } else {
                                    Forbidden.add(D.getID());
                                }
                                Graph BufferGraph = createAtomicGraph(V, D);
                                Graph parentRes = exploreAttackPath2(D, Forbidden, graph);

                                //One parent of the AND is missing -> Delete the whole branch
                                if (parentRes == null) {
                                    return null;
                                } else {
                                    Buffers.add(mergeGraphs(BufferGraph, parentRes));
                                }
                            } else {
                                return null;
                            }
                        }
                    }
                }
                for (Graph Buffer1 : Buffers) {
                    if (Buffer1 == null) {
                        return null;
                    }
                }
                for (Graph Buffer : Buffers) {
                    Result = mergeGraphs(Result, Buffer);
                }
            }
            return Result;
        }
        if (V.getType().equals(ORVertex.getType())) {
            if (predecessors != null) {
                Graph Buffer = null;
                boolean atLeastOnePath = false;
                for (Vertex D : predecessors) {
                    if (D != null) {
                        if (D.getType().equals(LEAFVertex.getType())) {
                            Buffer = mergeGraphs(Buffer, createAtomicGraph(V, D));
                            atLeastOnePath = true;
                        } else if (D.getType().equals(ANDVertex.getType())) {
                            Graph TempBuffer = exploreAttackPath2(D, Forbidden, graph);
                            if (TempBuffer != null) {
                                Buffer = mergeGraphs(Buffer, mergeGraphs(createAtomicGraph(V, D), TempBuffer));
                                atLeastOnePath = true;
                            }
                        }
                    }
                }
                if (!atLeastOnePath) {
                    return null;
                } else
                    return Buffer;
            }
        }
        return null;
    }

    /**
     * Merge two graphs in a new graph
     *
     * @param successor   the first graph
     * @param predecessor the secon graph
     * @return the merged graph
     */
    public static Graph mergeGraphs(Graph successor, Graph predecessor) {
        Graph result;
        if (successor == null) {
            return predecessor;
        }
        if (predecessor == null) {
            return successor;
        }
        Arc[] ArcsBuffer = new Arc[successor.getArcs().length];
        Vertex[] VertexBuffer = new Vertex[successor.getVertices().length];

        System.arraycopy(successor.getArcs(), 0, ArcsBuffer, 0, successor.getArcs().length);
        for (int k = 0; k < predecessor.getArcs().length; k++) {
            if (existsInSet(predecessor.getArcs()[k], successor.getArcs()) == 1) {
                Arc[] TempBuffer = new Arc[ArcsBuffer.length + 1];
                System.arraycopy(ArcsBuffer, 0, TempBuffer, 0, ArcsBuffer.length);
                TempBuffer[TempBuffer.length - 1] = predecessor.getArcs()[k];
                ArcsBuffer = TempBuffer;
            }
        }

        System.arraycopy(successor.getVertices(), 0, VertexBuffer, 0, successor.getVertices().length);
        double[] VertexIDs = new double[successor.getVertices().length];
        for (int h = 0; h < successor.getVertices().length; h++) {
            VertexIDs[h] = successor.getVertices()[h].getID();
        }
        for (int k = 0; k < predecessor.getVertices().length; k++) {
            if (existsInSet(predecessor.getVertices()[k].getID(), VertexIDs) == 1) {
                Vertex[] TempBuffer = new Vertex[VertexBuffer.length + 1];
                System.arraycopy(VertexBuffer, 0, TempBuffer, 0, VertexBuffer.length);
                TempBuffer[TempBuffer.length - 1] = predecessor.getVertices()[k];
                VertexBuffer = TempBuffer;
            }
        }

        Map<Integer, Vertex> vertexMap = new HashMap<>(predecessor.getVertexMap());
        for (Vertex vertex : successor.getVertexMap().values() ) {
            if (!vertexMap.containsKey(vertex.getID())) {
                vertexMap.put(vertex.getID(), vertex);
            }
        }
        result = new Graph(ArcsBuffer, VertexBuffer, vertexMap);
        return result;
    }

    /**
     * Get one vertex with a specified ID
     *
     * @param vertices the list of vertices
     * @param VertexID the vertex to search
     * @return the Vertex of the set
     */
    public static Vertex getVertex(Vertex[] vertices, double VertexID) {
        for (Vertex vertice : vertices) {
            if (vertice.getID() == VertexID) {
                return new Vertex(vertice);
            }
        }
        return null;
    }

    /**
     * Check if a forbidden vertex of V1 is found in V2
     *
     * @param V1 the vertices to search
     * @param V2 the list of forbidden vertices
     * @return 0 if forbidden vertex is found, else return 1
     */
    public static int checkForbiddenVertex(Vertex[] V1, Vertex[] V2) {
        int result = 1;
        if (V1 != null && V2 != null) {
            for (Vertex aV1 : V1) {
                for (Vertex aV2 : V2) {
                    if (aV1.getID() == aV2.getID()) {
                        return 0;
                    }
                }
            }
        }
        return result;
    }

    /**
     * Check if a forbidden vertex V1 is found in V2
     *
     * @param V1 The vertex to search
     * @param V2 the list of forbidden vertices
     * @return 0 if forbidden vertex is found, else return 1
     */
    public static int checkForbiddenVertex(Vertex V1, Vertex[] V2) {
        int result = 1;
        if (V1 != null && V2 != null) {
            for (Vertex aV2 : V2) {
                if (V1.getID() == aV2.getID()) {
                    return 0;
                }
            }
        }
        return result;
    }
}

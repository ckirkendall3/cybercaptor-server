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

/**
 * Class used to represent an attack path
 *
 * @author K. M.
 */
public class AttackPaths {

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
            Arrays.parallelSetAll(GraphTable, i -> exploreAttackPath2(Targets[i], new HashSet<>(), AttackGraph));
            return GraphTable;
        } else {
            return null;
        }
    }

    /**
     * Explore the attack path from node V
     *
     * @param V         the starting vertex
     * @param Forbidden the list of forbidden vertices
     * @param graph     the attack graph
     * @return the created attack path
     */
    private static Graph exploreAttackPath2(Vertex V, Set<Integer> Forbidden, Graph graph) {
        Vertex LEAFVertex = new Vertex(0, "", 0.0, "LEAF");
        Vertex ORVertex = new Vertex(0, "", 0.0, "OR");
        Vertex ANDVertex = new Vertex(0, "", 0.0, "AND");
        Graph Result = null;

        // Must reset the reference so we don't modify the incoming map
        Forbidden = new HashSet<>(Forbidden);

        List<Vertex> predecessors = V.getPredecessors();
        if (V.getType().equals(ANDVertex.getType())) {
            if (predecessors != null) {
                List<Graph> Buffers = new ArrayList<>();
                for (Vertex D : predecessors) {
                    if (D != null) {
                        if (D.getType().equals(LEAFVertex.getType())) {
                            Buffers.add(createAtomicGraph(V, D));
                        } else if (D.getType().equals(ORVertex.getType())) {
                            if (!Forbidden.contains(D.getID())) {
                                if (Forbidden.isEmpty()) {
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
            if ( Forbidden.isEmpty() ) {
                Forbidden.add(V.getID());
            }
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
    private static Graph mergeGraphs(Graph successor, Graph predecessor) {
        if (successor == null) {
            return predecessor;
        }
        if (predecessor == null) {
            return successor;
        }

        Set<Arc>             predecessorArcs      = predecessor.getArcs();
        Map<Integer, Vertex> predecessorVertexMap = predecessor.getVertexMap();

        predecessorArcs.addAll(successor.getArcs());
        predecessorVertexMap.putAll(successor.getVertexMap());

        return new Graph(predecessorArcs, predecessorVertexMap);
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
}

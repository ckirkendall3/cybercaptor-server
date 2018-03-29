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

import org.fiware.cybercaptor.server.scoring.types.Graph;
import org.fiware.cybercaptor.server.scoring.types.Vertex;
import org.fiware.cybercaptor.server.scoring.types.VertexType;

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
            AttackGraph.preProcessGraph();
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
        Graph Result = null;

        // Must reset the reference so we don't modify the incoming map
        Forbidden = new HashSet<>(Forbidden);

        List<Vertex> predecessors = V.getPredecessors();
        switch (V.getType()) {
            case AND: {
                if (checkForbidden(predecessors, Forbidden)) {
                    return null;
                }
                Result = V.getPredecessorsGraph();
                List<Graph> Buffers = new ArrayList<>();
                for (Vertex D : predecessors) {
                    switch (D.getType()) {
                        case LEAF:
                            Buffers.add(D.getSuccessorGraphs().get(V.getID()));
                            break;

                        case OR:
                            Forbidden.add(D.getID());
                            Graph parentRes = exploreAttackPath2(D, Forbidden, graph);

                            //One parent of the AND is missing -> Delete the whole branch
                            if (parentRes == null) {
                                return null;
                            } else {
                                Graph BufferGraph = D.getSuccessorGraphs().get(V.getID());

                                if (BufferGraph == null) {
                                    BufferGraph = Graph.mergeGraphs(Graph.createAtomicGraph(V, D), parentRes);
                                }
                                Buffers.add(BufferGraph);
                            }
                            break;

                        case AND:
                            break;

                    }
                }
                if (Result == null) {
                    for (Graph Buffer : Buffers) {
                        Result = Graph.mergeGraphs(Result, Buffer);
                    }
                }

                return Result;
            }

            case OR: {
                List<Graph> Buffers = new ArrayList<>();
                for (Vertex D : predecessors) {
                    switch (D.getType()) {
                        case LEAF:
                            Buffers.add(D.getSuccessorGraphs().get(V.getID()));
                            break;

                        case AND:
                            if (Forbidden.isEmpty()) {
                                Forbidden.add(V.getID());
                            }
                            Graph parentRes = exploreAttackPath2(D, Forbidden, graph);

                            //One parent of the AND is missing -> Delete the whole branch
                            if (parentRes != null) {
                                Graph BufferGraph = D.getSuccessorGraphs().get(V.getID());

                                if (BufferGraph == null) {
                                    BufferGraph = Graph.mergeGraphs(Graph.createAtomicGraph(V, D), parentRes);
                                }
                                Buffers.add(BufferGraph);
                            }
                            break;

                        case OR:
                            break;
                    }
                }

                if ( V.getPredecessorsGraph() != null && predecessors.size() == Buffers.size() ) {
                    Result = V.getPredecessorsGraph();
                } else {
                    for (Graph Buffer : Buffers) {
                        Result = Graph.mergeGraphs(Result, Buffer);
                    }
                }

                return Result;
            }

            case LEAF:
                break;
        }

        return null;
    }

    /**
     * Check the forbidden set for any of the vertices
     *
     * @param vertices  Vertices to check
     * @param forbidden Set of forbidden ids
     * @return true if there is a forbidden vertex
     */
    private static boolean checkForbidden(List<Vertex> vertices, Set<Integer> forbidden) {
        for (Vertex vertex : vertices) {
            if (vertex.getType().equals(VertexType.OR) && forbidden.contains(vertex.getID())) {
                return true;
            }
        }
        return false;
    }

}

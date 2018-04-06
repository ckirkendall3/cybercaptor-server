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
            //System.out.println(System.currentTimeMillis() + " (main): Preprocessing Graph");
            AttackGraph.preProcessGraph();
            //System.out.println(System.currentTimeMillis() + "(main): Exploring Attack Paths");
            Graph[] GraphTable = new Graph[Targets.length];
            Arrays.parallelSetAll(GraphTable, i -> exploreAttackPathJump(Targets[i],
                    new HashSet<>(Collections.singletonList(Targets[i].getID()))));
            return GraphTable;
        } else {
            return null;
        }
    }

    /**
     * Explore the attack path = generate the attack paths
     *
     * @param Targets     the targets nodes in the attack graph
     * @param AttackGraph the attack graph
     * @return the list of attack paths
     */
    public static Graph[] main2(Vertex[] Targets, Graph AttackGraph) {

        if (Targets != null) {
            AttackGraph.preProcessGraph();
            Graph[] GraphTable = new Graph[Targets.length];
            Arrays.parallelSetAll(GraphTable, i -> exploreAttackPath(Targets[i], new HashSet<>(), AttackGraph));
            return GraphTable;
        } else {
            return null;
        }
    }

    public static Graph exploreAttackPathJump(Vertex V, Set<Integer> Forbidden) {
        System.out.println(System.currentTimeMillis() + "(main): exploreAttackPath2 for vertex " + V.getID());
        HashSet<Graph> graphs = exploreAttackPath2(V, Forbidden, new HashSet<Integer>());
        if (graphs == null || graphs.isEmpty()) {
            return null;
        }
        System.out.println(System.currentTimeMillis() + "(main): mergeGraphs(" + graphs.size() + ") for vertex " + V.getID());
        return Graph.mergeGraphs(graphs);
    }

    /**
     * Explore the attack path from node V
     *
     * @param V         the starting vertex
     * @param Forbidden the list of forbidden vertices
     * @return the created attack path
     */
    private static HashSet<Graph> exploreAttackPath2(Vertex V, Set<Integer> Forbidden, Set<Integer> completed) {
        HashSet<Graph> Result = null;
        HashSet<Graph> Buffers = new HashSet<>();

        // Must reset the reference so we don't modify the incoming map
        Forbidden = new HashSet<>(Forbidden);

        List<Vertex> predecessors = V.getPredecessors();
        int numCompleted = 0;
        Set<Integer> currentVertexCompleted = new HashSet<>();
        if (V.getType() == VertexType.AND) {
            if (checkForbidden(predecessors, Forbidden)) {
                return null;
            }
            for (Vertex D : predecessors) {
                if (D.getType() == VertexType.LEAF) {
                    Buffers.add(V.getPredecessorAtomicGraphs().get(D.getID()));
                    currentVertexCompleted.add(D.getID());
                    numCompleted++;
                } else if (D.getType() == VertexType.OR) {
                    //System.out.println(String.format(format, 'O', D.getID()).replaceAll(" ", "."));
                    HashSet<Graph> parentRes = exploreAttackPath2(D, Forbidden, completed);

                    //One parent of the AND is missing -> Delete the whole branch
                    if (parentRes == null) {
                        return null;
                    } else {
                        Buffers.add(V.getPredecessorAtomicGraphs().get(D.getID()));
                        Buffers.addAll(parentRes);
                        if (completed.contains(D.getID())) {
                            numCompleted++;
                        }
                    }
                }
            }
        } else if (V.getType() == VertexType.OR) {
            for (Vertex D : predecessors) {
                boolean predComplete = completed.contains(D.getID());
                if (D.getType() == VertexType.LEAF) {
                    if (!predComplete) {
                        Buffers.add(V.getPredecessorAtomicGraphs().get(D.getID()));
                        currentVertexCompleted.add(D.getID());
                    }
                    numCompleted++;
                } else if (D.getType() == VertexType.AND) {
                    if (!predComplete) {
                        HashSet<Graph> parentRes = exploreAttackPath2(D, Forbidden, completed);

                        if (parentRes != null) {
                            Buffers.add(V.getPredecessorAtomicGraphs().get(D.getID()));
                            Buffers.addAll(parentRes);
                            if (completed.contains(D.getID())) {
                                numCompleted++;
                            }
                        }
                    } else {
                        Buffers.add(V.getPredecessorAtomicGraphs().get(D.getID()));
                        numCompleted++;
                    }
                }
            }
        }

        if (numCompleted == predecessors.size()) {
            completed.add(V.getID());
        }
        completed.addAll(currentVertexCompleted);

        if (!Buffers.isEmpty()) {
            Result = Buffers;
        }

        return Result;
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
            if (vertex.getType().equals(VertexType.OR)) {
                if (forbidden.contains(vertex.getID())) {
                    return true;
                } else {
                    forbidden.add(vertex.getID());
                }
            }
        }
        return false;
    }

    private static Graph exploreAttackPath(Vertex V, Set<Integer> Forbidden, Graph graph) {
        Graph Result = null;

        // Must reset the reference so we don't modify the incoming map
        Forbidden = new HashSet<>(Forbidden);

        List<Vertex> predecessors = V.getPredecessors();
        if (V.getType().equals(VertexType.AND)) {
            if (predecessors != null) {
                List<Graph> Buffers = new ArrayList<>();
                for (Vertex D : predecessors) {
                    if (D != null) {
                        if (D.getType().equals(VertexType.LEAF)) {
                            Buffers.add(createAtomicGraph(V, D));
                        } else if (D.getType().equals(VertexType.OR)) {
                            if (!Forbidden.contains(D.getID())) {
                                if (Forbidden.isEmpty()) {
                                    Forbidden.add(D.getID());
                                } else {
                                    Forbidden.add(D.getID());
                                }
                                Graph BufferGraph = createAtomicGraph(V, D);
                                Graph parentRes = exploreAttackPath(D, Forbidden, graph);

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
        if (V.getType().equals(VertexType.OR)) {
            if (Forbidden.isEmpty()) {
                Forbidden.add(V.getID());
            }
            if (predecessors != null) {
                Graph Buffer = null;
                boolean atLeastOnePath = false;
                for (Vertex D : predecessors) {
                    if (D != null) {
                        if (D.getType().equals(VertexType.LEAF)) {
                            Buffer = mergeGraphs(Buffer, createAtomicGraph(V, D));
                            atLeastOnePath = true;
                        } else if (D.getType().equals(VertexType.AND)) {
                            Graph TempBuffer = exploreAttackPath(D, Forbidden, graph);
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

        Set<Arc> predecessorArcs = predecessor.getArcs();
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
        return Graph.createAtomicGraph(V, D);
    }
}

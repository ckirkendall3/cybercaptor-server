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
    private Set<Vertex> Vertices;

    /**
     * Instantiates a new Graph.
     *
     * @param arcs     the arcs
     * @param vertices the vertices
     */
    public Graph(Arc[] arcs, Vertex[] vertices) {
        Arcs = new HashSet<>(Arrays.asList(arcs));
        Vertices = new HashSet<>(Arrays.asList(vertices));
    }

    /**
     * Instantiates a new Graph.
     *
     * @param arcs     the arcs
     * @param vertices the vertices
     */
    public Graph(Set<Arc> arcs, Set<Vertex> vertices) {
        Arcs = arcs;
        Vertices = vertices;
    }

    /**
     * Get vertices on type and fact.
     *
     * @param vertices the vertices
     * @param type     the type
     * @return the vertex [ ]
     */
    public static Vertex[] getVerticesOnTypeAndFact(Vertex[] vertices, String type) {
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
    public static Vertex[] getVerticesOnType(Vertex[] vertices, String type) {
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
     * Get arcs.
     *
     * @return the arcs
     */
    public Set<Arc> getArcs() {
        return Arcs;
    }


    public Set<Vertex> getVertices() {
        return Vertices;
    }

    /**
     * Loops through all the arcs and configures the predecessors for all the
     * vertices.
     */
    public void getPredecessors() {
        Map<Integer, Vertex> vertexMap = new HashMap<>();
        for (Vertex vertex : Vertices) {
            vertexMap.put(vertex.getID(), vertex);
        }
        //the first for loop is to get the cardinality of the query result
        for (Arc arc : Arcs) {
            vertexMap.get(arc.getSource()).addPredecessor(vertexMap.get(arc.getDestination()));
        }
    }

}

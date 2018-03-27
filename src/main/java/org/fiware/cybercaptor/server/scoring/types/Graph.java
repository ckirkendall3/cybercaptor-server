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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Class used to represent a graph
 *
 * @author K. M.
 */
public class Graph {

    /**
     * The arcs of the graph
     */
    private Arc[] Arcs;

    private Vertex[] Vertices;

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
        setArcs(arcs);
        setVertices(vertices);
        initializeVertexMap();
    }

    /**
     * Instantiates a new Graph.
     *
     * @param arcs     the arcs
     * @param vertexMap the vertices
     */
    public Graph(Arc[] arcs, Map<Integer, Vertex> vertexMap) {
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
     * @return the arc [ ]
     */
    public Arc[] getArcs() {
        return Arcs;
    }

    /**
     * Sets arcs.
     *
     * @param arcs the arcs
     */
    public void setArcs(Arc[] arcs) {
        Arcs = arcs;
    }

    /**
     * Get vertices.
     *
     * @return the vertex [ ]
     */
    public Vertex[] getVertices() {
        return Vertices;
    }

    /**
     * Sets vertices.
     *
     * @param vertices the vertices
     */
    public void setVertices(Vertex[] vertices) {
        Vertices = vertices;
    }

    private void initializeVertexMap() {
        VertexMap = new HashMap<>();
        for (Vertex vertex : Vertices)
        {
            VertexMap.put(vertex.getID(), vertex);
        }
    }

    public Map<Integer, Vertex> getVertexMap() {
        return VertexMap;
    }

    /**
     * Loops through all the arcs and configures the predecessors for all the
     * vertices.
     */
    public void getPredecessors() {
        //the first for loop is to get the cardinality of the query result
        for (Arc arc : Arcs) {
            VertexMap.get(arc.getSource()).addPredecessor(VertexMap.get(arc.getDestination()));
        }
    }

}

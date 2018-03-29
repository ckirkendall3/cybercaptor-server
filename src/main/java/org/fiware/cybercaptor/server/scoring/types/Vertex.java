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

import org.fiware.cybercaptor.server.attackgraph.ImpactMetric;

import java.util.*;

/**
 * Class used to represent the vertex of a graph
 *
 * @author K. M.
 */
public class Vertex {

    /**
     * The vertex ID
     */
    private int ID;

    /**
     * The vertex Fact
     */
    private String Fact;

    /**
     * The vertex metric
     */
    private double MulvalMetric;

    /**
     * The vertex type enum
     */
    private VertexType Type;

    /**
     * The vertex predecessor set
     */
    private List<Vertex> Predecessors = new ArrayList<>();

    /**
     * Graphs by successors
     */
    private Map<Integer, Graph> SuccessorGraphs = new HashMap<>();

    /**
     * Graph of predecessors
     */
    private Graph PredecessorsGraph = null;

    /**
     * Map of atomic maps to all this vertices predecessors.
     */
    private Map<Integer, Graph> PredecessorAtomicGraphs = new HashMap<>();

    /**
     * The vertex impact metrics
     */
    private ImpactMetric[] ImpactMetrics = null;

    /**
     * Instantiates a new Vertex.
     *
     * @param id     the id
     * @param fact   the fact
     * @param metric the metric
     * @param type   the type
     */
    public Vertex(int id, String fact, double metric, VertexType type) {
        ID = id;
        Fact = fact;
        MulvalMetric = metric;
        setType(type);
    }

    /**
     * Instantiates a new Vertex.
     *
     * @param vertex the vertex
     */
    public Vertex(Vertex vertex) {
        ID = vertex.ID;
        Fact = vertex.Fact;
        MulvalMetric = vertex.MulvalMetric;
        setType(vertex.getType());
    }

    /**
     * Gets iD.
     *
     * @return the iD
     */
    public int getID() {
        return ID;
    }

    /**
     * Sets iD.
     *
     * @param id the id
     */
    public void setID(int id) {
        ID = id;
    }

    /**
     * Gets fact.
     *
     * @return the fact
     */
    public String getFact() {
        return Fact;
    }

    /**
     * Sets fact.
     *
     * @param fact the fact
     */
    public void setFact(String fact) {
        Fact = fact;
    }

    /**
     * Gets mulval metric.
     *
     * @return the mulval metric
     */
    public double getMulvalMetric() {
        return MulvalMetric;
    }

    /**
     * Sets mulval metric.
     *
     * @param metric the metric
     */
    public void setMulvalMetric(double metric) {
        MulvalMetric = metric;
    }


    /**
     * Gets type enum.
     *
     * @return the type enum
     */
    public VertexType getType() {
        return Type;
    }

    /**
     * Sets type enum.
     *
     * @param type the type enum
     */
    public void setType(VertexType type) {
        Type = type;
    }

    //END CODE KM

    /**
     * Get impact metrics.
     *
     * @return the impact metric [ ]
     */
    public ImpactMetric[] getImpactMetrics() {
        return ImpactMetrics;
    }

    /**
     * Sets impact metrics.
     *
     * @param impactMetrics the impact metrics
     */
    public void setImpactMetrics(ImpactMetric[] impactMetrics) {
        ImpactMetrics = impactMetrics;
    }

    public List<Vertex> getPredecessors() {
        return Predecessors;
    }

    public void addPredecessor(Vertex vertex) {
        Predecessors.add(vertex);
    }

    public Map<Integer, Graph> getSuccessorGraphs() {
        return SuccessorGraphs;
    }

    public void addSuccessorGraph(int successorId, Graph graph) {
        SuccessorGraphs.put(successorId, graph);
    }

    public Graph getPredecessorsGraph() {
        return PredecessorsGraph;
    }

    public void setPredecessorsGraph(Graph predecessorsGraph) {
        PredecessorsGraph = predecessorsGraph;
    }

    public Map<Integer, Graph> getPredecessorAtomicGraphs() {
        return PredecessorAtomicGraphs;
    }

    public void addPredecessorAtomicGraph(int id, Graph graph) {
        PredecessorAtomicGraphs.put(id, graph);
    }
}

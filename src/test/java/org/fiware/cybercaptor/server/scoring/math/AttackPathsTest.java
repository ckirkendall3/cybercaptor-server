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
import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.VLAN;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.junit.Assert;
import org.junit.Test;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.fail;

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
        Graph predecessor = createGraph(20000, 4000, 4000);

        long millis = System.currentTimeMillis();
        for ( int i = 0; i < 10000; i++) {
            Set<Arc> successorArcs = new HashSet<>(successor.getArcs());
            Set<Arc> predecessorArcs = new HashSet<>(predecessor.getArcs());
            Set<Vertex> successorVertices = new HashSet<>(successor.getVertices());
            Set<Vertex> predecessorVertices = new HashSet<>(predecessor.getVertices());
            AttackPaths.mergeGraphs(
                    new Graph(successorArcs, successorVertices),
                    new Graph(predecessorArcs, predecessorVertices));
        }
        System.out.print("Time: " + (System.currentTimeMillis() - millis));
    }

    private Graph createGraph(int numArcs, int numVertices, int startId) {
        Set<Vertex> vertices = new HashSet<>();
        Set<Arc> arcs = new HashSet<>();

        int endId = startId + numVertices + 1;
        for (int i = startId; i < endId; i++) {
            vertices.add(new Vertex(i, "fact" + i, i, "type" + i));
        }

        for (int i = 0; i < numArcs; i++) {
            int source = ThreadLocalRandom.current().nextInt(startId, endId);
            int destination = ThreadLocalRandom.current().nextInt(startId, endId);
            arcs.add(new Arc(source, destination));
        }
        return new Graph(arcs, vertices);
    }
}

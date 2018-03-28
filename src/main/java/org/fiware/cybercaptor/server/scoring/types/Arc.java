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

import java.util.Objects;

/**
 * Class used to represent the arc of a graph
 *
 * @author K. M.
 */
public class Arc {

    /**
     * The source id
     */
    private int Source;

    /**
     * the destination id
     */
    private int Destination;

    /**
     * Instantiates a new Arc.
     *
     * @param source      the source id
     * @param destination the destination id
     */
    public Arc(int source, int destination) {
        Source = source;
        Destination = destination;
    }

    /**
     * Gets source.
     *
     * @return the source id
     */
    public int getSource() {
        return Source;
    }

    /**
     * Sets source.
     *
     * @param source the source id
     */
    public void setSource(int source) {
        Source = source;
    }

    /**
     * Gets destination.
     *
     * @return the destination id
     */
    public int getDestination() {
        return Destination;
    }

    /**
     * Sets destination.
     *
     * @param destination the destination id
     */
    public void setDestination(int destination) {
        Destination = destination;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Arc)) return false;
        Arc arc = (Arc) o;
        return Source == arc.Source &&
                Destination == arc.Destination;
    }

    @Override
    public int hashCode()
    {
        return (2^15) * Source + Destination;
    }
}

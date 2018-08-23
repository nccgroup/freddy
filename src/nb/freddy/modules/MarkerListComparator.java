// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

import java.util.Comparator;

/***********************************************************
 * Comparator class used to sort lists of HTTP
 * request/response markers.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class MarkerListComparator implements Comparator<int[]> {
    /*******************
     * Static instance
     ******************/
    private static MarkerListComparator _instance = null;

    /*******************
     * Get the static instance.
     *
     * @return
     ******************/
    public static MarkerListComparator getInstance() {
        if (_instance == null) {
            _instance = new MarkerListComparator();
        }
        return _instance;
    }

    /*******************
     * Compare two markers.
     *
     * @param marker1 The first marker.
     * @param marker2 The second marker.
     * @return An int describing which way to sort the two markers.
     ******************/
    public int compare(int[] marker1, int[] marker2) {
        return Integer.compare(marker1[0], marker2[0]);
    }
}

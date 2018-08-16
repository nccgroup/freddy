// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

/***********************************************************
 * Issue severity enum.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public enum SeverityRating {
    HIGH("High"),
    MEDIUM("Medium"),
    LOW("Low"),
    INFORMATION("Information"),
    FALSEPOSITIVE("False positive");

    //Severity string
    private final String _severity;

    /*******************
     * Construct from string.
     *
     * @param severity The severity string.
     ******************/
    SeverityRating(String severity) {
        _severity = severity;
    }

    /*******************
     * Convert severity value to string.
     *
     * @return The string representation of the enum value.
     ******************/
    public String toString() {
        return _severity;
    }
}

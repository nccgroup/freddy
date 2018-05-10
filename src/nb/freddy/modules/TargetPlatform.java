// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

/***********************************************************
 * Target platform enumeration.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public enum TargetPlatform {
	DOTNET(".NET"),
	JAVA("Java");
	
	//Platform name string
	private final String _name;
	
	/*******************
	 * Construct with name string.
	 * 
	 * @param name The corresponding name string for the enum value.
	 ******************/
	private TargetPlatform(String name) {
		_name = name;
	}
	
	/*******************
	 * Convert the enum value to a string.
	 * 
	 * @return The string name of the enum value.
	 ******************/
	public String toString() {
		return _name;
	}
}

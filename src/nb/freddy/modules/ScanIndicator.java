// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/***********************************************************
 * Wrapper for data to search for in requests or responses
 * to identify potentially vulnerable applications.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ScanIndicator {
	//Indicator data
	private final String _indicatorStr;
	private final Pattern _indicatorRegex;
	private final byte[] _indicatorBytes;
	
	/*******************
	 * Protected default constructor used by subclasses.
	 ******************/
	protected ScanIndicator() {
		_indicatorStr = null;
		_indicatorRegex = null;
		_indicatorBytes = null;
	}
	
	/*******************
	 * Create an indicator to detect a single string.
	 * 
	 * @param searchStr The string to search for.
	 ******************/
	public ScanIndicator(String searchStr) {
		if(searchStr == null || searchStr.length() == 0) {
			throw new IllegalArgumentException("ScanIndicator(String) must be called with a string length of at least 1 character.");
		}
		_indicatorStr = searchStr;
		_indicatorRegex = null;
		_indicatorBytes = null;
	}
	
	/*******************
	 * Create an indicator to detect a regex pattern.
	 * 
	 * @param searchPattern The regex pattern to search for.
	 ******************/
	public ScanIndicator(Pattern searchPattern) {
		if(searchPattern == null) {
			throw new IllegalArgumentException("ScanIndicator(Pattern) must be called with a valid Pattern object.");
		}
		_indicatorRegex = searchPattern;
		_indicatorStr = null;
		_indicatorBytes = null;
	}
	
	/*******************
	 * Create an indicator to detect raw bytes.
	 * 
	 * @param searchBytes The bytes to search for.
	 ******************/
	public ScanIndicator(byte[] searchBytes) {
		if(searchBytes == null || searchBytes.length == 0) {
			throw new IllegalArgumentException("ScanIndicator(byte[]) must be called with at least one byte.");
		}
		_indicatorBytes = searchBytes;
		_indicatorStr = null;
		_indicatorRegex = null;
	}
	
	/*******************
	 * Check whether the indicator is text-based and hence operates on a string
	 * rather than raw bytes.
	 * 
	 * @return True if the indicator is text-based.
	 ******************/
	public boolean isTextBased() {
		if(_indicatorStr != null || _indicatorRegex != null) {
			return true;
		}
		return false;
	}
	
	/*******************
	 * Find all instances of the given string within the target string.
	 * 
	 * @param matchStr The indicator string to search for.
	 * @param targetStr The string to search within.
	 * @return A list of int pairs marking the start and end indices of all instances of the indicator string.
	 ******************/
	protected ArrayList<int[]> findStringMatches(String matchStr, String targetStr) {
		ArrayList<int[]> matches = new ArrayList<int[]>();
		int currentOffset = 0;
		
		//Find and return all instances of the given indicator in the given string
		while((currentOffset = targetStr.indexOf(matchStr, currentOffset)) != -1) {
			matches.add(new int[] {currentOffset, currentOffset + matchStr.length()});
			currentOffset++;
		}
		return matches;
	}
	
	/*******************
	 * Find all instances of the given regex pattern within the target string.
	 * 
	 * @param matchPat The indicator pattern to search for.
	 * @param targetStr The string to search within.
	 * @return A list of int pairs marking the start and end indices of all instances of the indicator pattern.
	 ******************/
	protected ArrayList<int[]> findRegexMatches(Pattern matchPat, String targetStr) {
		ArrayList<int[]> matches = new ArrayList<int[]>();
		Matcher m;
		
		//Find and return all instances of the given indicator pattern in the given string
		m = matchPat.matcher(targetStr);
		while(m.find()) {
			matches.add(new int[] {m.start(), m.end()});
		}
		return matches;
	}
	
	/*******************
	 * Find all instances of the given byte array within the target byte array.
	 * 
	 * @param matchBytes The indicator byte array to search for.
	 * @param targetBytes The byte array to search within.
	 * @return A list of int pairs marking the start and end indices of all instances of the indicator pattern.
	 ******************/
	protected ArrayList<int[]> findByteMatches(byte[] matchBytes, byte[] targetBytes) {
		ArrayList<int[]> matches = new ArrayList<int[]>();
		boolean bFound;
		
		//Find and return all instances of the given indicator bytes in the given byte array
		for(int curPos = 0; curPos <= (targetBytes.length - matchBytes.length); ++curPos) {
			bFound = true;
			for(int i = 0; i < matchBytes.length; ++i) {
				if(targetBytes[curPos + i] != matchBytes[i]) {
					bFound = false;
					break;
				}
			}
			if(bFound == true) {
				matches.add(new int[] {curPos, curPos + matchBytes.length});
				curPos += matchBytes.length - 1;
			}
		}
		return matches;
	}
	
	/*******************
	 * Find all instances of a text-based indicator value in the given string
	 * and return a list if int pairs containing the start and end indices.
	 * 
	 * @param targetStr The string to search within.
	 * @return A list of int pairs marking the start and end indices of all instances of the indicator.
	 ******************/
	public ArrayList<int[]> findInstances(String targetStr) {
		ArrayList<int[]> matches;
		
		//Bail if not a text-based indicator
		if(isTextBased() == false) {
			throw new IllegalStateException("ScanIndicator.findInstances(String) called on a byte-based indicator.");
		}
		
		//Find and return all instances of the indicator in the given string
		if(_indicatorStr != null) {
			matches = findStringMatches(_indicatorStr, targetStr);
		} else {
			matches = findRegexMatches(_indicatorRegex, targetStr);
		}
		return matches;
	}
	
	/*******************
	 * Find all instances of a byte-based indicator value in the given string
	 * and return a list if int pairs containing the start and end indices.
	 * 
	 * @param targetData The byte array to search within.
	 * @return A list of int pairs marking the start and end indices of all instances of the indicator.
	 ******************/
	public ArrayList<int[]> findInstances(byte[] targetData) {
		//Bail if this is a text-based indicator
		if(isTextBased() == true) {
			throw new IllegalStateException("ScanIndicator.findInstances(byte[]) called on a text-based indicator.");
		}
		
		//Find and return all instances of the indicator in the given byte array
		return findByteMatches(_indicatorBytes, targetData);
	}
}

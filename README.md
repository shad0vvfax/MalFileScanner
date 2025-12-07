This was mostly all coded in Python using Claude AI. I tweaked a few small things myself. It was designed to scan binary files for suspicious strings or code. It has a little bit of everything in it. It's main use would be for malware analysis. Im sure it has some quirks, so feel free to change it however you like.  

ex: python3 bin-scanner.py 'file'  

Arguments are listed below.  

'file', help='Binary file to scan'  
'-m', '--min-length', type=int, default=4, help='Minimum string length (default: 4)'  
'-e', '--encoding', choices=['ascii', 'unicode', 'both'], default='both', help='String encoding to extract'  
'-o', '--output', help='Output file for results'  
'-v', '--verbose', action='store_true' help='Show all findings including potential false positives'  
'--no-filter', action='store_true', help='Disable false positive filtering (show everything)'  

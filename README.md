'file',  
'-m', '--min-length', type=int, default=4, help='Minimum string length (default: 4)'  
'-e', '--encoding', choices=['ascii', 'unicode', 'both'], default='both', help='String encoding to extract'  
'-o', '--output', help='Output file for results'  
'-v', '--verbose', action='store_true', help='Show all findings including potential false positives'  
'--no-filter', action='store_true', help='Disable false positive filtering (show everything)'  

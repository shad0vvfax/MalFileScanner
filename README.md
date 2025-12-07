This was all coded in Python using Claude AI. It was designed to scan binary files for suspicious strings or code. It has a little bit of everything in it. It's main use would be for malware analysis. Im sure it has some quirks, so feel free to change it however you like.

ex: python3 bin-scanner.py 'file'

Arguments are listed below.

parser = argparse.ArgumentParser(
        description='Scan binary files for potentially suspicious strings'
    )
    parser.add_argument('file', help='Binary file to scan')
    parser.add_argument('-m', '--min-length', type=int, default=4,
                       help='Minimum string length (default: 4)')
    parser.add_argument('-e', '--encoding', choices=['ascii', 'unicode', 'both'],
                       default='both', help='String encoding to extract')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show all findings including potential false positives')
    parser.add_argument('--no-filter', action='store_true',
                       help='Disable false positive filtering (show everything)')

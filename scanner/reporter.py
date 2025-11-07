# scanner/reporter.py
from scanner.scanner import scan_file

def report(findings: dict):
    """
    Print formatted scan findings.
    """
    if 'error' in findings:
        print("Error: " + findings['error'])
        return
    
    if not findings:
        print("No issues found. Configuration is safe!")
        return
    
    print("Potential Issues Detected:")
    for resource, issues in findings.items():
        print(f"\nResource: {resource}")
        for issue in issues:
            print(f" - {issue}")

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python -m scanner.reporter <config_file>")
        sys.exit(1)
    file_path = sys.argv[1]
    findings = scan_file(file_path)
    report(findings)

if __name__ == '__main__':
    main()
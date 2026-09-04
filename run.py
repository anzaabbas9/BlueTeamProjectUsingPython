"""
Entry point for the Blue Team Log Analyzer.

Usage:
    python run.py --file sample_logs/auth.log --threshold 3
"""

from analyzer.cli import main

if __name__ == '__main__':
    main()

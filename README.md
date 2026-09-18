delpy is a simple, cross-platform, playground-level Data Loss Prevention (DLP) project written in Python. It is designed as an educational project to demonstrate how a basic DLP system can monitor files, inspect their contents, and identify potentially sensitive information using configurable patterns.

delpy monitors a configured directory using the Python watchdog library. When a file event occurs, delpy reads the file content and checks it against the patterns defined in signatures/delpy-pattern.txt. Each pattern has a name, regular expression, and sensitivity level, allowing the student to see how content-based detection works.

Execution instruction:
Console#1 execute: python3 src/delpy.py
Console#2 execute: echo "Test card 4111 1111 1111 1111" > /tmp/test-card.txt

This will generate an alert:
21:52:23 ALERT delpy: signature=Credit Card sensitivity=HIGH host=acme001 srcip=192.168.1.32 file=test-card.txt

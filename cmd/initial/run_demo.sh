#!/bin/bash

# FHIPE Precomputed Table Demo Script

echo "========================================"
echo "FHIPE Precomputed Table Demo"
echo "========================================"
echo ""

# Clean up any existing table
if [ -f "precomputed_table.gob" ]; then
    echo "Removing existing precomputed table..."
    rm precomputed_table.gob
    echo ""
fi

echo "Running precomputed table example..."
echo "This will:"
echo "  1. Precompute the lookup table"
echo "  2. Save it to disk"
echo "  3. Compare BSGS vs Table lookup performance"
echo ""
echo "Press Enter to continue..."
read

# Run the program with input "2" for precomputed table example
echo "2" | go run .

echo ""
echo "========================================"
echo "Table has been saved to precomputed_table.gob"
echo "Run again to see instant table loading!"
echo "========================================"

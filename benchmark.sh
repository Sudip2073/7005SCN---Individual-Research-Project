#!/bin/bash

# ==============================================================================
# 7005SCN Individual Research Project - RQ3 Latency Data Collection
# This script measures the operational overhead of Shift-Left security controls.
# ==============================================================================

ITERATIONS=3
CSV_FILE="evidence/RQ3/pipeline_latency_data_$(date +%Y%m%d).csv"

# Ensure the evidence directory exists
mkdir -p evidence/RQ3

# Initialize the CSV file with headers
echo "Iteration,Model,Latency_Seconds" > "$CSV_FILE"

echo "=================================================="
echo " Starting Baseline Metrics (Build Only)"
echo "=================================================="
for i in $(seq 1 $ITERATIONS); do
  # Record start time
  START_TIME=$(date +%s%N)
  
  # Execution: Traditional Perimeter Baseline (Build Only)
  docker build -t benchmark-app:baseline$i . 
  
  # Record end time and calculate duration
  END_TIME=$(date +%s%N)
  DURATION=$(awk "BEGIN {printf \"%.3f\", ($END_TIME - $START_TIME) / 1000000000}")
  
  # Log to CSV and console
  echo "$i,Baseline,$DURATION" >> "$CSV_FILE"
  echo "Baseline Run $i: $DURATION seconds"
done

echo ""
echo "=================================================="
echo " Starting Secure DevSecOps Metrics (Build + SBOM + Scan)"
echo "=================================================="
for i in $(seq 1 $ITERATIONS); do
  # Record start time
  START_TIME=$(date +%s%N)
  
  # Execution: Shift-Left Enforcement (Build -> Attest -> Scan)
  docker build -t benchmark-app:secure$i . &> /dev/null &
  wait
  syft benchmark-app:secure$i -o cyclonedx-json=sbom$i.json &> /dev/null &
  wait
  trivy sbom sbom$i.json &> /dev/null &
  wait
  
  # Record end time and calculate duration
  END_TIME=$(date +%s%N)
  DURATION=$(awk "BEGIN {printf \"%.3f\", ($END_TIME - $START_TIME) / 1000000000}")
  
  # Log to CSV and console
  echo "$i,Secure,$DURATION" >> "$CSV_FILE"
  echo "Secure Run $i: $DURATION seconds"
done

echo ""
echo "✅ Benchmarking complete! Empirical data saved to $CSV_FILE"
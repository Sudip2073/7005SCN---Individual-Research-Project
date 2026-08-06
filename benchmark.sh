#!/bin/bash
set -euo pipefail

# ==============================================================================
# 7005SCN Individual Research Project - RQ3 Latency Data Collection
# This script measures the operational overhead of Shift-Left security controls.
# ==============================================================================

ITERATIONS=50
CSV_FILE="evidence/RQ3/granular_latency_data_$(date +%Y%m%d%H%M%S).csv"

# Ensure the evidence directory exists
mkdir -p evidence/RQ3

# Initialize the CSV file with our expanded headers
echo "Timestamp,Iteration,Pipeline_Type,Build_Time_Sec,SBOM_Time_Sec,Scan_Time_Sec,Total_Time_Sec" > "$CSV_FILE"

echo "=================================================="
echo " Starting Baseline Metrics (Build Only)"
echo "=================================================="
for i in $(seq 1 $ITERATIONS); do
  CURRENT_TIME=$(date "+%Y-%m-%d %H:%M:%S")
  
  # Measure Build Time
  T0=$(date +%s.%N)
  DOCKER_BUILDKIT=0 docker build -t benchmark-app:baseline . > /dev/null 2>&1
  T1=$(date +%s.%N)
  
  # Calculate Durations
  BUILD_TIME=$(echo "$T1 - $T0" | bc | awk '{printf "%.3f", $0}')
  
  # Baseline has no Syft or Trivy
  SBOM_TIME="0.000"
  SCAN_TIME="0.000"
  TOTAL_TIME=$BUILD_TIME
  
  # Log to CSV
  echo "$CURRENT_TIME,$i,Baseline,$BUILD_TIME,$SBOM_TIME,$SCAN_TIME,$TOTAL_TIME" >> "$CSV_FILE"
  echo "Baseline Run $i: Total $TOTAL_TIME sec"
done

echo ""
echo "=================================================="
echo " Starting Secure Metrics (Build + Syft + Trivy)"
echo "=================================================="
for i in $(seq 1 $ITERATIONS); do
  CURRENT_TIME=$(date "+%Y-%m-%d %H:%M:%S")
  
  # 1. Measure Build Time
  T0=$(date +%s.%N)
  DOCKER_BUILDKIT=0 docker build -t benchmark-app:secure . > /dev/null 2>&1
  
  # 2. Measure Syft (SBOM) Time
  T1=$(date +%s.%N)
  syft benchmark-app:secure -o cyclonedx-json=sbom.json > /dev/null 2>&1
  
  # 3. Measure Trivy (Scan) Time
  T2=$(date +%s.%N)
  trivy sbom sbom.json > /dev/null 2>&1
  T3=$(date +%s.%N)
  
  # Calculate Exact Durations
  BUILD_TIME=$(echo "$T1 - $T0" | bc | awk '{printf "%.3f", $0}')
  SBOM_TIME=$(echo "$T2 - $T1" | bc | awk '{printf "%.3f", $0}')
  SCAN_TIME=$(echo "$T3 - $T2" | bc | awk '{printf "%.3f", $0}')
  TOTAL_TIME=$(echo "$T3 - $T0" | bc | awk '{printf "%.3f", $0}')
  
  # Log to CSV
  echo "$CURRENT_TIME,$i,Secure,$BUILD_TIME,$SBOM_TIME,$SCAN_TIME,$TOTAL_TIME" >> "$CSV_FILE"
  echo "Secure Run $i: Build: ${BUILD_TIME}s | SBOM: ${SBOM_TIME}s | Scan: ${SCAN_TIME}s | Total: ${TOTAL_TIME}s"
done

echo ""
echo "✅ Granular benchmarking complete! Empirical data saved to $CSV_FILE"
#!/bin/bash

# Define constants for testing
NUM_EXEC=100 # Number of exsecutions
WAIT_TIME=5 # Time to wait for the QKD nodes to be ready
DB_KEY_DIST="\\\"results/key_distribution.out\\\"" # Path to the key distribution file results
DB_ENC_TIME="\\\"results/encryption_time.out\\\"" # Path to the encryption time file results

# Crear la carpeta "results" si no existe
if [ ! -d "results" ]; then
    echo "Creating 'results' directory..."
    mkdir results
else
    echo "'results' directory already exists."
fi

# Loop for NUM_WORKERS from 3 to 11 with increments of 2
for NUM_WORKERS in $(seq 3 2 11); do
    echo "Compiling and running for NUM_WORKERS=$NUM_WORKERS..."

    # Cambiar WAIT_TIME a 10 si NUM_WORKERS es 11
    # Change WAIT_TIME to 10 if NUM_WORKERS is 11 to avoid overload the QKD nodes
    if [ "$NUM_WORKERS" -eq 11 ]; then
        WAIT_TIME=10
    fi

    # Compile the code
    make clean
    make CFLAGS="-DNUM_WORKERS=$NUM_WORKERS -DNUM_EXEC=$NUM_EXEC -DWAIT_TIME=$WAIT_TIME -DDB_KEY_DIST=$DB_KEY_DIST -DDB_ENC_TIME=$DB_ENC_TIME"

    # Verificar si la compilación fue exitosa
    if [ $? -ne 0 ]; then
        echo "Compilation failed for NUM_WORKERS=$NUM_WORKERS. Skipping execution."
        continue
    fi

    # Execute the compiled code
    echo "Running or_relay_ext.o for NUM_WORKERS=$NUM_WORKERS..."
    ./or_relay_ext.o

    echo "Running key_relay.o for NUM_WORKERS=$NUM_WORKERS..."
    ./key_relay.o

    echo "Running trusted_node.o for NUM_WORKERS=$NUM_WORKERS..."
    ./trusted_node.o

    echo "Running or_relay for NUM_WORKERS=$NUM_WORKERS..."
    ./or_relay.o

    echo "Finished execution for NUM_WORKERS=$NUM_WORKERS."
    echo "---------------------------------------------"
done

make clean

echo "All executions completed."
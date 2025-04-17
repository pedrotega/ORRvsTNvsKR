import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Define the paths to the CSV files
results_dir = "results"
key_distribution_avs_csv = f"{results_dir}/key_distribution_avs.csv"
encryption_avs_csv = f"{results_dir}/encryption_time_avs.csv"

# Read the data from the CSV files
key_distribution_data = pd.read_csv(key_distribution_avs_csv)
encryption_data = pd.read_csv(encryption_avs_csv)

# Define the labels for the x-axis
x_labels = ["N-3", "N-5", "N-7", "N-9", "N-11"]
x = np.arange(len(x_labels))

# Extract the average values from the CSV for Key Distribution
or_ext_times_kd = key_distribution_data["OR-EXT"].tolist()
or_times_kd = key_distribution_data["OR"].tolist()
tn_times_kd = key_distribution_data["TN"].tolist()
kr_times_kd = key_distribution_data["KR"].tolist()

# Extract the average values from the CSV for Encryption Time
or_ext_times_enc = encryption_data["OR-EXT"].tolist()
or_times_enc = encryption_data["OR"].tolist()
tn_times_enc = encryption_data["TN"].tolist()
kr_times_enc = encryption_data["KR"].tolist()

# Define custom colors for the plots
colors = {
    "OR-EXT": "#568b87",  # Dark blue
    "TN": "#d47264",      # Green
    "OR": "#c9a66b",      # Orange
    "KR": "#ae282c"       # Red
}

# Create the plot for Key Distribution
plt.figure(figsize=(10, 6))
plt.errorbar(x, or_times_kd, fmt='s-', markersize=8, linewidth=3, label="Onion Routing Relay (ORR)", color=colors["OR"], capsize=5)
plt.errorbar(x, or_ext_times_kd, fmt='*-', markersize=10, linewidth=3, label="ORR - Extended (ORR-EXT)", color=colors["OR-EXT"], capsize=5)
plt.errorbar(x, tn_times_kd, fmt='o-', markersize=8, linewidth=3, label="Trusted Node (TN)", color=colors["TN"], capsize=5)
plt.errorbar(x, kr_times_kd, fmt='^-', markersize=8, linewidth=3, label="Key Relay (KR)", color=colors["KR"], capsize=5)

# Configure the plot
plt.yscale('log')  # Use a logarithmic scale for the y-axis
plt.xlabel("Number of nodes in the circuit", fontsize=14)
plt.ylabel("Key Distribution Time (μs)", fontsize=14)
plt.title("Key Distribution Time Comparison", fontsize=16)
plt.xticks(x, x_labels)
plt.legend(fontsize=14, loc='upper left')
plt.grid(True, which="both", linestyle='--', alpha=0.7)

# Save the Key Distribution plot as a PNG file
plt.savefig(f"{results_dir}/key_distribution_comparison.png", dpi=300)
plt.show()

# Create the plot for Encryption Time
plt.figure(figsize=(10, 6))
plt.errorbar(x, or_times_enc, fmt='s-', markersize=8, linewidth=3, label="Onion Routing Relay (ORR)", color=colors["OR"], capsize=5)
plt.errorbar(x, or_ext_times_enc, fmt='*-', markersize=10, linewidth=3, label="ORR - Extended (ORR-EXT)", color=colors["OR-EXT"], capsize=5)
plt.errorbar(x, tn_times_enc, fmt='o-', markersize=8, linewidth=3, label="Trusted Node (TN)", color=colors["TN"], capsize=5)
plt.errorbar(x, kr_times_enc, fmt='^-', markersize=8, linewidth=3, label="Key Relay (KR)", color=colors["KR"], capsize=5)

# Configure the plot
plt.yscale('log')  # Use a logarithmic scale for the y-axis
plt.xlabel("Number of nodes in the circuit", fontsize=14)
plt.ylabel("Encryption Time (μs)", fontsize=14)
plt.title("Encryption Time Comparison", fontsize=16)
plt.xticks(x, x_labels)
plt.legend(fontsize=14, loc='center left', bbox_to_anchor=(0.53, 0.66))
plt.grid(True, which="both", linestyle='--', alpha=0.7)

# Save the Encryption Time plot as a PNG file
plt.savefig(f"{results_dir}/encryption_time_comparison.png", dpi=300)
plt.show()
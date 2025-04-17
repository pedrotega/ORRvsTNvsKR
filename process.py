import pandas as pd
import os

# Define the paths to the files
results_dir = "results"
encryption_file = os.path.join(results_dir, "encryption_time.out")
key_distribution_file = os.path.join(results_dir, "key_distribution.out")
encryption_csv = os.path.join(results_dir, "encryption_time.csv")
key_distribution_csv = os.path.join(results_dir, "key_distribution.csv")
encryption_avs_csv = os.path.join(results_dir, "encryption_time_avs.csv")
key_distribution_avs_csv = os.path.join(results_dir, "key_distribution_avs.csv")

def process_file_to_csv(input_file, output_csv):
    """Reads a file, transposes rows and columns, and saves the result to a CSV file."""
    try:
        # Read the archive ignoring the first element (timestamp)
        data = pd.read_csv(input_file, header=None)
        data = data.iloc[:, 1:-1]  # Ignore first and last columns
        data.columns = ["Name"] + list(range(1, len(data.columns))) 

        # Transpose the DataFrame
        transposed_data = data.set_index("Name").transpose()

        # Store the dataframe in a CSV file
        transposed_data.to_csv(output_csv)
        print(f"CSV file generated: {output_csv}")
    except FileNotFoundError:
        print(f"Error: File {input_file} does not exist.")
    except Exception as e:
        print(f"Error processing file {input_file}: {e}")

def remove_first_column(input_csv, output_csv):
    """Removes the first column from a CSV file and saves the result."""
    try:
        data = pd.read_csv(input_csv)
        
        data = data.iloc[:, 1:]
        
        data.to_csv(output_csv, index=False)
        print(f"CSV file without first column: {output_csv}")
    except FileNotFoundError:
        print(f"Error: El archivo {input_csv} no existe.")
    except Exception as e:
        print(f"Error procesando el archivo {input_csv}: {e}")

encryption_avs_csv = os.path.join(results_dir, "encryption_time_avs.csv")
key_distribution_avs_csv = os.path.join(results_dir, "key_distribution_avs.csv")

def calculate_averages(input_csv, output_csv):
    """Calculates averages grouped by model and saves the result to a new CSV file."""
    try:
        data = pd.read_csv(input_csv)

        grouped_columns = {
            "OR-EXT": [col for col in data.columns if col.startswith("OR-EXT")],
            "KR": [col for col in data.columns if col.startswith("KR")],
            "TN": [col for col in data.columns if col.startswith("TN")],
            "OR": [col for col in data.columns if col.startswith("OR-") and not col.startswith("OR-EXT")]
        }

        averages = pd.DataFrame(columns=["OR-EXT", "KR", "TN", "OR"])

        for i, nodes in enumerate([3, 5, 7, 9, 11]):
            row = {}
            for group_name, columns in grouped_columns.items():
                node_columns = [col for col in columns if f"-{nodes}" in col]
                row[group_name] = data[node_columns].mean(axis=1).mean()
            averages.loc[i] = row

        averages.to_csv(output_csv, index=False)
        print(f"CSV file with averages: {output_csv}")
    except FileNotFoundError:
        print(f"Error: File {input_csv} does not exist.")
    except Exception as e:
        print(f"Error processing file {input_csv}: {e}")



def main():
    # Process the files and generate the transposed CSVs
    process_file_to_csv(encryption_file, encryption_csv)
    process_file_to_csv(key_distribution_file, key_distribution_csv)

    # Remove the first column from the transposed CSVs
    remove_first_column(encryption_csv, encryption_csv)
    remove_first_column(key_distribution_csv, key_distribution_csv)

    # Compute averages for encryption and key distribution
    calculate_averages(encryption_csv, encryption_avs_csv)
    calculate_averages(key_distribution_csv, key_distribution_avs_csv)

if __name__ == "__main__":
    main()
import xml.etree.ElementTree as ET

# File path to the XML file
file_path = "latest.xml"

# Subdirectory patterns to filter paths
subdirectory_patterns = [
    "native\\FileParser\\FeatureExtractor",
    "native\\FileParser\\FileParser\\"
]

def source_file(root):
    """
    Function to filter and return source file IDs and their paths based on subdirectory patterns.
    """
    source_files_dict = {}  

    for source_file in root.findall(".//source_file"):
        path = source_file.get("path")
        source_id = source_file.get("id")
        if path and source_id:
            for pattern in subdirectory_patterns:
                if pattern in path:
                    source_files_dict[source_id] = path
                    break

    return source_files_dict

def print_functions_grouped_by_file(root, source_files):
    """
    Function to print functions grouped by the source file they belong to.
    """
    file_function_map = {file_id: [] for file_id in source_files}  # Initialize a map for functions by file

    for function in root.findall(".//function"):
        for range_elem in function.findall(".//range"):
            source_id = range_elem.get("source_id")
            if source_id in source_files:
                line_coveraged = int(function.get("lines_covered")) + int(function.get("lines_partially_covered"))
                total_lines = line_coveraged + int(function.get("lines_not_covered"))
                line_coverage_avg = round((line_coveraged / total_lines) * 100, 2)
                function_data = {
                    "id": function.get("id"),
                    "name": function.get("name"),
                    "block_coverage": function.get("block_coverage"),
                    "line_coverage": line_coverage_avg,
                }
                file_function_map[source_id].append(function_data)
                break
    countLineFileCount = 0 
    totalnumoffiles = 0
    for file_id, functions in file_function_map.items():
        totalnumoffiles+=1
        if functions:
            # print(f"\nSource File: {source_files[file_id]} (ID: {file_id})")
            # print(f"{'Name':<50}{'Block Coverage':<20}{'Line Coverage':<20}")
            # print("-" * 75)

            total_line_coverage = 0
            for func in functions:
                # print(f"{func['name']:<50}{func['block_coverage']:<20}{func['line_coverage']:<20}")
                total_line_coverage += func['line_coverage']

            average_line_coverage = round(total_line_coverage / len(functions), 2)
            if(average_line_coverage <= 95):
                # print(total_line_coverage, len(functions))
                countLineFileCount+=1
                print(f"\n{source_files[file_id]} : {average_line_coverage}%")
        else:
            print(f"\nSource File: {source_files[file_id]} (ID: {file_id})")
            print("No functions found.")
    print("Total Files with less than 95% line coverage: ", countLineFileCount)
    print("Total Files: ", totalnumoffiles)

try:
    # Parse the XML file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Filter and collect source files
    source_files = source_file(root)

    # Print functions grouped by file
    print_functions_grouped_by_file(root, source_files)

except FileNotFoundError:
    print(f"Error: File '{file_path}' not found.")
except ET.ParseError as e:
    print(f"Error: Failed to parse XML file. {e}")
